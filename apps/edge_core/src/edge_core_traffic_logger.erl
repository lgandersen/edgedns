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
         stats_log/2,
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

-record(state, {logging_frequency,
                query_log
               }).

-ifdef(query_logging).

-define(QUERY_LOG, ?query_logging).
-define(QUERY_LOG(IP, Query, Response),
    gen_server:cast(?SERVER, {log_query, {IP, Query, Response}})
).

-else.

-define(QUERY_LOG, no_file).
-define(QUERY_LOG(IP, Query, Response), ok).

-endif.


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

log_query(_IP, _Query, _Response) ->
    ?QUERY_LOG(_IP, _Query, _Response).

dampening_activated(IP) ->
    gen_server:cast(?SERVER, {dampening_activated, IP}).

dampening_removed(IP) ->
    gen_server:cast(?SERVER, {dampening_removed, IP}).

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================
%% @private
init([]) ->
    LoggingFrequency = edge_core_config:stats_log_frequency(),
    timer:send_after(LoggingFrequency, log_stats),
    {ok, #state { logging_frequency = LoggingFrequency,
                  query_log         = open_file(?QUERY_LOG)
                }}.

%% @private
handle_call(_Request, _From, State) ->
    Reply = ok,
    {reply, Reply, State}.

%% @private
handle_cast({log_query, {IP, Query, Response}}, #state { query_log = LogFile } = State) ->
    case inet_dns:decode(Response) of
        {ok, Data} ->
            [QueryType] = extract_query_type(Data),
            LogEntry = [IP, erlang:system_time(milli_seconds), size(Query), size(Response), QueryType],
            io:fwrite(LogFile, "~p|~p|~p|~p|~p~n", LogEntry);

        Other ->
            lager:warning("Unable to decode DNS response: ~p", [Other])
    end,
    {noreply, State};

handle_cast({dampening_activated, IP}, State) ->
    stats_log("~p dampening activated.~n", [IP]),
    {noreply, State};

handle_cast({dampening_removed, IP}, State) ->
    stats_log("~p dampening removed.~n", [IP]),
    {noreply, State};

handle_cast(_Msg, State) ->
    {noreply, State}.

%% @private
handle_info(log_stats, #state { logging_frequency = NextLogging } = State) ->
    NDampened = edge_core_traffic_monitor:get_dampened_ip_masks(),
    {Blocked, Allowed, Whitelisted} = log_stats(),
    stats_log("dampened ips: ~p - queries ~p/~p/~p~n", [NDampened, Blocked, Allowed, Whitelisted]),
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

 %% @private
-spec open_file(string()) -> file:io_device().
open_file(no_file) ->
    no_file;

open_file(FileName) ->
    {ok, LogFile} = file:open(FileName, [write]),
    LogFile.

-ifdef(TEST).
stats_log(Msg, Args) ->
    logging_receiver ! {log, Msg, Args}.
-else.
stats_log(Msg, Args) ->
    lager:notice(Msg, Args).
-endif.
