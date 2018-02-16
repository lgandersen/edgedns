%%%-------------------------------------------------------------------
%%% @author Lasse Grinderslev Andersen
%%% @copyright (C) 2017, Lasse Grinderslev Andersen
%%% @doc
%%%
%%% @end
%%%-------------------------------------------------------------------
-module(edge_core_resolver).

-include_lib("kernel/src/inet_dns.hrl").
-include_lib("stdlib/include/ms_transform.hrl").

-include("edgedns.hrl").

-behaviour(gen_statem).

%% API
-export([
        start_link/3,
        resolve/5
        ]).

%% States
-export([
         active/3
        ]).

%% gen_statem callbacks
-export([
         init/1,
         callback_mode/0,
         terminate/3,
         code_change/4
        ]).

-define(SERVER, ?MODULE).

-define(MessageID(Id), #dns_rec { header = #dns_header { id = Id }}).
-define(RESPONSE(Packet), {udp, _Socket, _IP, _Port, Packet}).

-record(state, {
          socket             :: gen_udp:socket(),
          blocking_threshold :: pos_integer(),
          dns_server         :: {gen_udp:socket(), inet:ip_address(), inet:port_number()},
          last_id            :: integer(),
          enable_dampening        :: boolean(),
          silent             :: boolean(),
          pending_requests   :: ets:tid()}).

-type state() :: #state {}.

%%===================================================================
%% API
%%===================================================================

%% @doc Start a new (linked) resolver process
%%
%% This spawns and links a resolver process to the UDP listener
%%
%% @end
-spec start_link(inet:port_number(), inet:ip_address(), inet:port_number()) -> {ok, pid()} | ignore | {error, term()}.
start_link(LocalPort, DNSServerIP, DNSServerPort) ->
    gen_statem:start_link(?MODULE, [LocalPort, DNSServerIP, DNSServerPort], []).

resolve(Resolver, Socket, IP, Port, Packet) ->
    gen_statem:cast(Resolver, {resolve, {Socket, IP, Port, Packet}}).


%%===================================================================
%% gen_statem callbacks
%%===================================================================
%% @private
callback_mode() -> state_functions.

%% @private
-spec init([]) -> {ok, idle, state()} | {stop, term()}.
init([LocalPort, DNSServerIP, DNSServerPort]) ->
    lager:info("Starting resolver using port ~p", [LocalPort]),
    case gen_udp:open(LocalPort, [binary, inet, {active, once}, {reuseaddr, true}]) of
        {ok, Socket} ->
            Table = ets:new(pending_requests, [set, protected]),
            DNSServer = {Socket, DNSServerIP, DNSServerPort},
            StateData = #state { dns_server          = DNSServer,
                                 pending_requests    = Table,
                                 silent              = edge_core_config:silent(),
                                 last_id             = rand:uniform(round(math:pow(2, 16)) - 1),
                                 blocking_threshold  = edge_core_config:blocking_threshold(),
                                 enable_dampening    = edge_core_config:enable_dampening(),
                                 socket              = Socket },
            make_cleanup_reminder(),
            {ok, active, StateData};

        {error, _} = Error ->
            {stop, Error}
    end.

%% @private
terminate(_Reason, _StateName, _State) ->
    ok.

%% @private
code_change(_OldVsn, StateName, State, _Extra) ->
    {ok, StateName, State}.

%%===================================================================
%% States
%%===================================================================
%% @private
active(cast, {resolve, {Socket, IP, Port, Request}}, State) ->
    %% Received a request to resolve by the upstream DNS server
    Scoring = lookup_score(IP),
    Whitelisted = whitelisted(IP),
    Sender = {Socket, IP, Port},
    NewState = process_request(Scoring, Whitelisted, Sender, Request, State),
    {keep_state, NewState};

active(info, {udp, Socket, _DNSServerIP, _DNSServerPort, Response}, State) ->
    %% Got a response from the upstream DNS server
    process_response(Response, State),
    inet:setopts(Socket, [{active, once}]),
    {keep_state, State};

active(info, cleanup_table, #state { pending_requests = Table } = State) ->
    Now = erlang:system_time(second),
    MatchSpec = ets:fun2ms(
        fun({_, _, _, _, _, _, Timestamp})
              when Now - Timestamp > 3 -> true
        end),
    _NumDeleted = ets:select_delete(Table, MatchSpec),
    make_cleanup_reminder(),
    {keep_state, State}.

%%===================================================================
%% Internal functions
%%===================================================================
%% @private
process_request(Score, not_whitelisted, Sender, Request, #state { enable_dampening   = DampeningEnabled,
                                                                  blocking_threshold = BlockingThreshold } = State) when Score > BlockingThreshold ->
    %% Ip is in the table and above threshold
    edge_core_traffic_monitor:register_query_status(blocked),
    case DampeningEnabled of
        true ->
            %% FIXME here should be an increase in score that does not depend on a response
            State;

        false ->
            forward_request(Sender, Request, State)
    end;

process_request(Score, not_whitelisted, Sender, Request, #state { blocking_threshold = BlockingThreshold } = State) when Score =< BlockingThreshold ->
    %% Ip is in the table and below threshold
    edge_core_traffic_monitor:register_query_status(allowed),
    forward_request(Sender, Request, State);

process_request(_Score, whitelisted, Sender, Request, State) ->
    %% Whitelisted and thus not blocked
    edge_core_traffic_monitor:register_query_status(whitelisted),
    forward_request(Sender, Request, State).


%% @private
forward_request(Sender, <<Id:2/binary, Request/binary>>, #state { pending_requests = Table,
                                                                  last_id          = LastInternalId,
                                                                  dns_server       = DNSServer } = State) ->
    InternalIdInteger = next_id(LastInternalId),
    InternalId = <<InternalIdInteger:16/big-integer>>,

    Element = {InternalId, Id, Sender, Request, erlang:system_time(second)},
    true = ets:insert(Table, Element),

    send_request(<<InternalId:2/binary, Request/binary>>, DNSServer),

    State#state { last_id = InternalIdInteger}.


%% @private
process_response(<<InternalId:2/binary, Response/binary>>, #state { pending_requests = Table} = State) ->

    case ets:lookup(Table, InternalId) of
        [{InternalId, Id, Sender, Request, _Timestamp}] ->
            true = ets:delete(Table, InternalId),
            FullResponse = <<Id:2/binary, Response/binary>>,
            {ListeningSocket, IP, Port} = Sender,
            send_response(ListeningSocket, IP, Port, FullResponse, State),
            edge_core_traffic_logger:log_query(IP, Request, FullResponse),
            edge_core_traffic_monitor:register_lookup(whitelisted(IP), IP, score(Request, Response));

        [] ->
            lager:warning("Error looking up pending query in table!")
    end.


%% @private
send_request(Packet, {Socket, IP, Port}) ->
    ok = gen_udp:send(Socket, IP, Port, Packet).


%% @private
send_response(_, _, _, _, #state { silent = true }) ->
    ok;

send_response(Socket, IP, Port, Response, _State) ->
    gen_udp:send(Socket, IP, Port, Response).


%% @private
score(Request, Response) ->
    RequestSize = size(Request),
    ResponseSize = size(Response),
    round( (RequestSize + ResponseSize) * (ResponseSize / RequestSize) ).

-define(MAX_INT16, 65535).

%% @private
next_id(LastId) ->
    ((LastId + 1) rem ?MAX_INT16) + 1.

%% @private
make_cleanup_reminder() ->
    erlang:send_after(5000, self(), cleanup_table).

%% @private
lookup_score(IP) ->
    case ets:lookup(?SCORE_TABLE, IP) of
        [] ->
            0;

        [{_IP, Score}] ->
            Score
    end.

%% @private
whitelisted(IP) ->
    case ets:lookup(?WHITELIST, IP) of
        [] ->
            not_whitelisted;

        [{IP}] ->
            whitelisted
    end.
