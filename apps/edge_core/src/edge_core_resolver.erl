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
          do_nothing         :: boolean(),
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
    gen_statem:cast(Resolver, {resolve, {Socket, IP, Port, Packet, self()}}).


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
                                 silent              = edge_core_config:silent(),
                                 last_id             = 1, %rand:uniform(round(math:pow(2, 16)) - 1),
                                 blocking_threshold  = edge_core_config:blocking_threshold(),
                                 do_nothing          = edge_core_config:do_nothing(),
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
active(cast, {resolve, {Socket, IP, Port, RequestRaw, Caller}}, #state {
                                                           blocking_threshold = BlockingThreshold,
                                                           do_nothing         = DoNothing,
                                                           last_id            = LastId } = State) ->
    %% Received a request to resolve at the DNS server
    IsBlocked = edge_core_traffic_monitor:is_blocked(IP, BlockingThreshold),
    NextId = case {IsBlocked, DoNothing} of
         {true, false} ->
            lager:notice("IP ~p is blocked.", [IP]),
            LastId;

         {true, true} ->
            process_request(Socket, IP, Port, RequestRaw, Caller, State);

         {false, _} ->
            process_request(Socket, IP, Port, RequestRaw, Caller, State)
    end,
    {keep_state, State#state { last_id = NextId }};

%% Got a response for the DNS server
active(info, {udp, Socket, _DNSServerIP, _DNSServerPort, Response}, State) ->
    case inet_dns:decode(Response) of
        {ok, Data} ->
            process_response(Data, State);

        Other ->
            lager:warning("kunne ikke dekode dns-svar: ~p", [Other])
    end,
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
process_request(Socket, IP, Port, RequestRaw, Caller, #state {pending_requests = Table,
                                                              last_id          = LastId,
                                                              dns_server       = DNSServer }) ->
    case inet_dns:decode(RequestRaw) of
         {ok, #dns_rec { header = Header = #dns_header { id = OldID }} = Request} ->
            InternalId = next_id(LastId),
            Element = {InternalId, OldID, Caller, Socket, IP, Port, RequestRaw, erlang:system_time(second)},
            true = ets:insert(Table, Element),
            ForwardRequest = inet_dns:encode(Request#dns_rec { header = Header#dns_header { id = InternalId }}),
            send_request(ForwardRequest, DNSServer),
            InternalId;

          Other ->
            lager:warning("Could not parse DNS request, failed with: ~p", [Other]),
            LastId
    end.


%% @private
process_response(?MessageID(InternalId) = Data, #state { pending_requests = Table} = State) ->
    case ets:lookup(Table, InternalId) of
        [{InternalId, OriginalId, _Caller, ListeningSocket, IP, Port, Request, _Timestamp}] ->
            true = ets:delete(Table, InternalId),
            DataOriginalId = Data?MessageID(OriginalId),
            ResponseOldID = inet_dns:encode(DataOriginalId),
            send_response(ListeningSocket, IP, Port, ResponseOldID, State),
            #dns_rec { qdlist = QuestionSection } = Data,
            QueryType = extract_query_type(QuestionSection),
            edge_core_traffic_logger:log_query(IP, Port, Request, ResponseOldID, QueryType),
            edge_core_traffic_monitor:register_lookup(IP, score(Request, ResponseOldID));

        [] ->
            lager:warning("Error looking up pending query in table!")
    end.


%% @private
send_request(Packet, {Socket, IP, Port}) ->
    ok = gen_udp:send(Socket, IP, Port, Packet).


%% @private
send_response(_, _, _, _, #state { silent = true }) ->
    ok;

send_response(Socket, IP, Port, Response, _) ->
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

extract_query_type(Query) ->
    extract_query_type(Query, []).


extract_query_type([{dns_query, _Name, Type, _Class} | Rest], Types) ->
    extract_query_type(Rest, [Type | Types]);

extract_query_type([], Types) ->
    Types.
