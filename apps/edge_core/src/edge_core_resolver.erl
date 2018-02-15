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
          no_blocking         :: boolean(),
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
                                 no_blocking         = edge_core_config:no_blocking(),
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
active(cast, {resolve, {Socket, IP, Port, Request}}, #state { blocking_threshold = BlockingThreshold,
                                                                 no_blocking        = DoNothing,
                                                                 last_id            = LastId } = State) ->
    %% Received a request to resolve at the DNS server
    IsBlocked = is_blocked(IP, BlockingThreshold),
    NextId = case {IsBlocked, DoNothing} of
         {true, false} ->
            LastId;

         {true, true} ->
            process_request({Socket, IP, Port}, Request, State);

         {false, _} ->
            process_request({Socket, IP, Port}, Request, State)
    end,
    {keep_state, State#state { last_id = NextId }};

%% Got a response for the DNS server
active(info, {udp, Socket, _DNSServerIP, _DNSServerPort, Response}, State) ->
    process_response(Response, State),
    inet:setopts(Socket, [{active, once}]),
    {keep_state, State};

active(info, cleanup_table, #state { pending_requests = Table } = StateData) ->
    Now = erlang:system_time(second),
    MatchSpec = ets:fun2ms(
        fun({_, _, _, _, _, _, Timestamp})
              when Now - Timestamp > 3 -> true
        end),
    _NumDeleted = ets:select_delete(Table, MatchSpec),
    make_cleanup_reminder(),
    {keep_state, StateData}.

%%===================================================================
%% Internal functions
%%===================================================================
%% @private
-spec is_blocked(inet:ip(), pos_integer()) -> boolean().
is_blocked(IP, BlockingThreshold) ->
    ScoreLookup = ets:lookup(?SCORE_TABLE, IP),
    WhiteListed = ets:lookup(?WHITELIST, IP),
    case {ScoreLookup, WhiteListed} of
        {[], []} ->
            %% Allowed, not whitelisted
            edge_core_traffic_monitor:register_query_status(allowed),
            false;

        {_, [{IP}]} ->
            %% Whitelisted and thus not blocked
            edge_core_traffic_monitor:register_query_status(whitelisted),
            false;

        {[{IP, Score}], _} when Score > BlockingThreshold ->
            %% Ip is in the table and above threshold
            edge_core_traffic_monitor:register_query_status(blocked),
            true;

        {[{IP, Score}], _} when Score =< BlockingThreshold ->
            %% Ip is in the table and below threshold
            edge_core_traffic_monitor:register_query_status(allowed),
            false
    end.


%% @private
process_request(Sender, <<Id:2/binary, Request/binary>>, #state { pending_requests = Table,
                                                                  last_id          = LastInternalId,
                                                                  dns_server       = DNSServer }) ->
    InternalIdInteger = next_id(LastInternalId),
    InternalId = <<InternalIdInteger:16/big-integer>>,

    Element = {InternalId, Id, Sender, Request, erlang:system_time(second)},
    true = ets:insert(Table, Element),

    FullRequest = <<InternalId:2/binary, Request/binary>>,
    send_request(FullRequest, DNSServer),
    stats_log:info("Incoming (no identifier): ~p", [Request]),
    InternalId.

%% @private
process_response(<<InternalId:2/binary, Response/binary>>, #state { pending_requests = Table} = State) ->

    case ets:lookup(Table, InternalId) of
        [{InternalId, Id, Sender, Request, _Timestamp}] ->
            true = ets:delete(Table, InternalId),
            FullResponse = <<Id:2/binary, Response/binary>>,
            {ListeningSocket, IP, Port} = Sender,
            stats_log:info("Outgoing (no identifier): ~p", [Response]),
            send_response(ListeningSocket, IP, Port, FullResponse, State),
            edge_core_traffic_logger:log_query(IP, Request, Response),
            edge_core_traffic_monitor:register_lookup(IP, score(Request, Response));

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

next_id(LastId) ->
    ((LastId + 1) rem ?MAX_INT16) + 1.

make_cleanup_reminder() ->
    erlang:send_after(5000, self(), cleanup_table).
