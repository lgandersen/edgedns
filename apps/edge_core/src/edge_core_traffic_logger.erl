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
         log_query/4]).

%% gen_server callbacks
-export([init/1,
         handle_call/3,
         handle_cast/2,
         handle_info/2,
         terminate/2,
         code_change/3]).

-define(SERVER, ?MODULE).

-define(LOG_TABLE, log_table).

-record(state, {table, query_log, stats_log, logging_frequency}).

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

log_query(IP, Query, Response, QueryType) ->
    gen_server:cast(?SERVER, {log_query, {IP, Query, Response, QueryType}}).

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================

%% @private
init([]) ->
    QueryLog = open_file(edge_core_config:query_log()),
    StatsLog = open_file(edge_core_config:stats_log()),
    LoggingFrequency = edge_core_config:stats_log_frequencey(),
    timer:send_after(LoggingFrequency, log_stats),
    {ok, #state { query_log         = QueryLog,
                  stats_log         = StatsLog,
                  logging_frequency = LoggingFrequency }}.

%% @private
handle_call(_Request, _From, State) ->
    Reply = ok,
    {reply, Reply, State}.

%% @private
handle_cast({log_query, _}, #state { query_log = no_file } = State) ->
    {noreply, State};

handle_cast({log_query, {IP, Query, Response, Data}}, #state { query_log = LogFile } = State) ->
    QueryType = extract_query_type(Data),
    io:fwrite(LogFile, "~p|~p|~p|~p|~p~n", [IP, erlang:system_time(milli_seconds), size(Query), size(Response), QueryType]),
    {noreply, State};

handle_cast(log_stats, #state { stats_log = no_file } = State) ->
    {noreply, State};

handle_cast(log_stats, #state { stats_log = File, logging_frequency = NextLogging } = State) ->
    NDampened = edge_core_traffic_monitor:get_dampened_ip_masks(),
    {Blocked, Allowed, Whitelisted} = log_stats(),
    io:fwrite(File, "~p|~p|~p|~p~n", [NDampened, Blocked, Allowed, Whitelisted]),
    timer:send_after(NextLogging, log_stats),
    {noreply, State};

handle_cast(_Msg, State) ->
    {noreply, State}.

%% @private
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

%% @private
-spec open_file(string() | no_file) -> file:io_device().
open_file(no_file) ->
    no_file;

open_file(FileName) ->
    {ok, LogFile} = file:open(FileName, [write]),
    LogFile.
