%%%-------------------------------------------------------------------
%%% @author Lasse Grinderslev Andersen
%%% @copyright (C) 2017, Lasse Grinderslev Andersen
%%% @doc
%%%
%%% @end
%%%-------------------------------------------------------------------
-module(edge_core_traffic_logger).

-include_lib("kernel/src/inet_dns.hrl").

-behaviour(gen_server).

%% API
-export([start_link/0,
         log_query/5]).

%% gen_server callbacks
-export([init/1,
         handle_call/3,
         handle_cast/2,
         handle_info/2,
         terminate/2,
         code_change/3]).

-define(SERVER, ?MODULE).

-define(LOG_TABLE, log_table).

-record(state, {table, log_file}).

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

log_query(IP, Port, Query, Response, QueryType) ->
    gen_server:cast(?SERVER, {log_query, IP, Port, Query, Response, QueryType}).

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================

%% @private
init([]) ->
    {ok, LogFile} = file:open("log.csv", [write]),
    {ok, #state { log_file = LogFile }}.

%% @private
handle_call(_Request, _From, State) ->
    Reply = ok,
    {reply, Reply, State}.

%% @private
handle_cast({log_query, IP, _Port, Query, Response, Data}, #state { log_file = LogFile } = State) ->
    QueryType = extract_query_type(Data),
    io:fwrite(LogFile, "~p|~p|~p|~p|~p~n", [IP, erlang:system_time(milli_seconds), size(Query), size(Response), QueryType]),
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
extract_query_type(#dns_rec { qdlist = QuestionSection }) ->
    extract_query_type(QuestionSection, []).


extract_query_type([{dns_query, _Name, Type, _Class} | Rest], Types) ->
    extract_query_type(Rest, [Type | Types]);

extract_query_type([], Types) ->
    Types.
