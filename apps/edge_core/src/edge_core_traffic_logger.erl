%%%-------------------------------------------------------------------
%%% @author Lasse Grinderslev Andersen
%%% @copyright (C) 2017, Lasse Grinderslev Andersen
%%% @doc
%%%
%%% @end
%%%-------------------------------------------------------------------
-module(edge_core_traffic_logger).

-include_lib("kernel/src/inet_dns.hrl").

-include("edgedns.hrl").

-behaviour(gen_server).

%% API
-export([start_link/0,
         log_query/3,
         dampening_activated/1,
         dampening_removed/1]).

%% gen_server callbacks
-export([init/1,
         handle_call/3,
         handle_cast/2,
         handle_info/2,
         terminate/2,
         code_change/3]).

-define(SERVER, ?MODULE).

-define(LOG_TABLE, log_table).

-record(state, { logging_frequency }).

%%%===================================================================
%%% API
%%%===================================================================

%%--------------------------------------------------------------------
%% @doc
%% Starts the server
%%
%% @end
%%--------------------------------------------------------------------
start_link() ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

log_query(IP, Query, Response) ->
    gen_server:cast(?SERVER, {log_query, {IP, Query, Response}}).

dampening_activated(IP) ->
    gen_server:cast(?SERVER, {dampening_activated, IP}).

dampening_removed(IP) ->
    gen_server:cast(?SERVER, {dampening_removed, IP}).

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================

%% @private
init([]) ->
    LoggingFrequency = edge_core_config:stats_log_frequencey(),
    timer:send_after(LoggingFrequency, log_stats),
    {ok, #state { logging_frequency = LoggingFrequency }}.

%% @private
handle_call(_Request, _From, State) ->
    Reply = ok,
    {reply, Reply, State}.

%% @private
handle_cast({log_query, {IP, Query, Response}}, State) ->
    %% FIXME this should be enabled through a macro such that no query-parsing is
    %% taking place unless this full logging is turned on
    case inet_dns:decode(Response) of
        {ok, Data} ->
            [QueryType] = extract_query_type(Data),
            Log = [IP, erlang:system_time(milli_seconds), size(Query), size(Response), QueryType],
            query_log:info("~p|~p|~p|~p|~p~n", Log);

        Other ->
            lager:warning("Unable to decode DNS response: ~p", [Other])
    end,
    {noreply, State};

handle_cast({dampening_activated, IP}, State) ->
    stats_log:info("~p dampening activated.~n", [IP]),
    {noreply, State};

handle_cast({dampening_removed, IP}, State) ->
    stats_log:info("~p dampening removed.~n", [IP]),
    {noreply, State};

handle_cast(_Msg, State) ->
    {noreply, State}.

%% @private
handle_info(log_stats, #state { logging_frequency = NextLogging } = State) ->
    NDampened = edge_core_traffic_monitor:get_dampened_ip_masks(),
    {Blocked, Allowed, Whitelisted} = log_stats(),
    stats_log:info("dampened ips: ~p - queries ~p/~p/~p~n", [NDampened, Blocked, Allowed, Whitelisted]),
    timer:send_after(NextLogging, log_stats),
    {noreply, State};

handle_info(_Info, State) ->
    {noreply, State}.

%% @private
terminate(_Reason, _State) ->
    ok.

%% @private
code_change(_OldVsn, State, _Extra) ->
        {ok, State}.

%%%===================================================================
%%% Internal functions
%%%===================================================================
%% @private
-spec log_stats() -> {non_neg_integer(), non_neg_integer(), non_neg_integer()}.
log_stats() ->
    Blocked = ets:lookup_element(?STAT_TABLE, blocked, 2),
    Allowed = ets:lookup_element(?STAT_TABLE, allowed, 2),
    Whitelisted = ets:lookup_element(?STAT_TABLE, whitelisted, 2),
    edge_core_traffic_monitor:reset_stat_table(),
    {Blocked, Allowed, Whitelisted}.

%% @private
extract_query_type(#dns_rec { qdlist = QuestionSection }) ->
    extract_query_type(QuestionSection, []).


extract_query_type([{dns_query, _Name, Type, _Class} | Rest], Types) ->
    extract_query_type(Rest, [Type | Types]);

extract_query_type([], Types) ->
    Types.
