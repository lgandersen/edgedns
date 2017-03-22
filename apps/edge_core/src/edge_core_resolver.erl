%%%-------------------------------------------------------------------
%%% @author Lasse Grinderslev Andersen
%%% @copyright (C) 2017, Lasse Grinderslev Andersen
%%% @doc
%%%
%%% @end
%%%-------------------------------------------------------------------
-module(edge_core_resolver).

-behaviour(gen_statem).

%% API
-export([
        start_link/3,
        resolve/4
        ]).

%% States
-export([
         idle/3,
         resolving/3
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
          socket     :: gen_udp:socket(),
          blocking_threshold :: pos_integer(),
          dns_server :: {gen_udp:socket(), inet:ip_address(), inet:port_number()},
          request    :: term(), % be TODO more precise
          queue = [] :: [term()]}).

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
            DNSServer = {Socket, DNSServerIP, DNSServerPort},
            StateData = #state { dns_server          = DNSServer,
                                 blocking_threshold  = edge_core_config:blocking_threshold(),
                                 socket              = Socket },
            {ok, idle, StateData};

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
idle(cast, {resolve, Request}, StateData) ->
    case process_queue(StateData#state { queue = [Request] }) of
        {empty_queue, NewStateData} ->
            {keep_state, NewStateData};

        {processing_request, NewStateData} ->
            {next_state, resolving, NewStateData}
    end.


%% @private
resolving(cast, {resolve, Request}, #state { queue = Queue } = StateData) ->
    {keep_state, StateData#state { queue = [Request | Queue] }};

resolving(info, ?RESPONSE(Response), StateData) ->
    lager:notice("Response received!"),
    process_response(Response, StateData),
    case process_queue(StateData) of
        {empty_queue, NewStateData} ->
            {next_state, idle, NewStateData};

        {processing_request, NewStateData} ->
            {keep_state, NewStateData}
    end;


resolving(Event, EventData, StateData) ->
    lager:warning("Unkown event ~p with eventdata ~p", [Event, EventData]),
    {keep_state, StateData}.


%%===================================================================
%% Internal functions
%%===================================================================

%% @private
process_response(Response, #state { socket     = Socket,
                                    request    = {IP, Port, Request, Caller} }) ->
    Caller ! {response_received, {IP, Port, Response}},
    inet:setopts(Socket, [{active, once}]),
    edge_core_traffic_logger:log_query(IP, Port, Request, Response),
    edge_core_traffic_monitor:register_lookup(IP, score(Request, Response)).


%% @private
process_queue(#state { queue = Queue } = StateData) when length(Queue) =:= 0 ->
    lager:notice("No more requests left in queue"),
    {empty_queue, StateData#state{ request = undefined }};

process_queue(#state { dns_server         = DNSServer,
                       queue              = Queue,
                       blocking_threshold = BlockingThreshold } = StateData) when length(Queue) > 0 ->

    %% We have more requests in our queue so process the next one
    {IP, _Port, Packet, _Caller} = NewRequest = lists:last(Queue),

    %% Update our state
    NewQueue = lists:droplast(Queue),

    case edge_core_traffic_monitor:is_blocked(IP, BlockingThreshold) of
        true ->
            lager:notice("IP Address ~p is blocked!", [IP]),
            process_queue(StateData#state { queue = NewQueue });

        false ->
            lager:notice("Sending request ~p to DNSserver ~p", [NewRequest, DNSServer]),
            send(Packet, DNSServer),
            NewStateData = StateData#state { queue   = NewQueue,
                                             request = NewRequest
            },
            {processing_request, NewStateData}
    end.

%% @private
send(Packet, {Socket, IP, Port}) ->
    ok = gen_udp:send(Socket, IP, Port, Packet).

%% @private
score(Request, Response) ->
    RequestSize = size(Request),
    ResponseSize = size(Response),
    round( (RequestSize + ResponseSize) * (ResponseSize / RequestSize) ).
