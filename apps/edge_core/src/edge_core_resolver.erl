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

-behaviour(gen_statem).

%% API
-export([
        start_link/3,
        resolve/4
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

-define(RESPONSE(Packet), {udp, _Socket, _IP, _Port, Packet}).

-record(state, {
          socket             :: gen_udp:socket(),
          blocking_threshold :: pos_integer(),
          dns_server         :: {gen_udp:socket(), inet:ip_address(), inet:port_number()},
          last_id            :: integer(),
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

resolve(Resolver, IP, Port, Packet) ->
    gen_statem:cast(Resolver, {resolve, {IP, Port, Packet, self()}}).


%%===================================================================
%% gen_statem callbacks
%%===================================================================
%% @private
callback_mode() -> state_functions.

%% @private
-spec init([]) -> {ok, idle, state()} | {stop, term()}.
init([LocalPort, DNSServerIP, DNSServerPort]) ->
    lager:warning("Starting resolver using port ~p", [LocalPort]),
    case gen_udp:open(LocalPort, [binary, inet, {active, once}, {reuseaddr, true}]) of
        {ok, Socket} ->
            Table = ets:new(pending_requests, [set, protected]),
            DNSServer = {Socket, DNSServerIP, DNSServerPort},
            StateData = #state { dns_server          = DNSServer,
                                 pending_requests    = Table,
                                 last_id             = 1, %rand:uniform(round(math:pow(2, 16)) - 1),
                                 blocking_threshold  = edge_core_config:blocking_threshold(),
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
active(cast, {resolve, {IP, Port, Request, Caller}}, #state { pending_requests   = Table,
                                                              blocking_threshold = BlockingThreshold,
                                                              last_id            = LastId,
                                                              dns_server         = DNSServer } = StateData) ->
    %% Received a request to resolve at the DNS server
    NextId = case edge_core_traffic_monitor:is_blocked(IP, BlockingThreshold) of
        true ->
            lager:notice("IP ~p is blocked.", [IP]),
            LastId;

        false ->
            case inet_dns:decode(Request) of
                 {ok, #dns_rec { header = #dns_header { id = OldID }} = Data} ->
                    InternalId = next_id(LastId),
                    Element = {InternalId, OldID, Caller, IP, Port, Request, erlang:system_time(second)},
                    true = ets:insert(Table, Element),
                    NewPacket = inet_dns:encode(Data#dns_rec { header = #dns_header { id = InternalId }}),
                    send(NewPacket, DNSServer),
                    InternalId;
                  Other ->
                    lager:warning("Could not parse DNS request, failed with: ~p", [Other]),
                    LastId
            end
    end,
    {keep_state, StateData#state { last_id = NextId }};

%% Got a response for the DNS server
active(info, {udp, Socket, DNSServerIP, DNSServerPort, Response}, #state { pending_requests = Table,
                                                                           dns_server       = {Socket, DNSServerIP, DNSServerPort}} = StateData) ->
    %lager:warning("received response from our dns server"),
    case inet_dns:decode(Response) of
        {ok, #dns_rec { header = #dns_header { id = InternalId }} = Data} ->
            case ets:lookup(Table, InternalId) of
                [{NewID, OriginalId, Caller, IP, Port, Request, _Timestamp}] ->
                    true = ets:delete(Table, NewID),
                    ResponseOldID = inet_dns:encode(Data#dns_rec { header = #dns_header { id = OriginalId }}),
                    Caller ! {response_received, {IP, Port, ResponseOldID}},
                    #dns_rec { qdlist = QuestionSection } = Data,
                    QueryType = extract_query_type(QuestionSection),
                    %lager:warning("~p", [QueryType]),
                    edge_core_traffic_logger:log_query(IP, Port, Request, Response, QueryType),
                    edge_core_traffic_monitor:register_lookup(IP, score(Request, Response));
                [] ->
                    lager:warning("Fejlslagent opslag i tabellen!")
            end;

        Other ->
            lager:warning("kunne ikke dekode dns-svar: ~p", [Other])
    end,
    inet:setopts(Socket, [{active, once}]),
    {keep_state, StateData};

active(info, cleanup_table, #state { pending_requests = Table } = StateData) ->
    Now = erlang:system_time(second),
    MatchSpec = ets:fun2ms(
        fun({_, _, _, _, _, _, Timestamp})
              when Now - Timestamp > 3 -> true
        end),
    _NumDeleted = ets:select_delete(Table, MatchSpec),
    %lager:warning("Timed out connections discarded: ~p", [NumDeleted]),
    make_cleanup_reminder(),
    {keep_state, StateData}.

%%===================================================================
%% Internal functions
%%===================================================================
%% @private
send(Packet, {Socket, IP, Port}) ->
    ok = gen_udp:send(Socket, IP, Port, Packet).

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

extract_query_type(Query) ->
    extract_query_type(Query, []).


extract_query_type([{dns_query, _Name, Type, _Class} | Rest], Types) ->
    extract_query_type(Rest, [Type | Types]);

extract_query_type([], Types) ->
    Types.
