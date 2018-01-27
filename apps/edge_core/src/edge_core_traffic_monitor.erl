%%%-------------------------------------------------------------------
%%% @author Lasse Grinderslev Andersen
%%% @copyright (C) 2017, Lasse Grinderslev Andersen
%%% @doc
%%%
%%% @end
%%%-------------------------------------------------------------------
-module(edge_core_traffic_monitor).

-behaviour(gen_server).

%% API
-export([start_link/0,
         register_lookup/2,
         register_query_status/1,
         reset_stat_table/0
        ]).

%% gen_server callbacks
-export([init/1,
         handle_call/3,
         handle_cast/2,
         handle_info/2,
         terminate/2,
         code_change/3]).

-define(SERVER, ?MODULE).

-include("edgedns.hrl").

-include_lib("stdlib/include/ms_transform.hrl").

-record(state, {score_table        :: ets:tid(),
                stat_table         :: ets:tid(),
                whitelist          :: ets:tid(),
                decay_rate         :: float(),
                blocking_threshold :: pos_integer()}).

%%===================================================================
%% API
%%===================================================================

%%--------------------------------------------------------------------
%% @doc Starts the traffic monitor process
%%
%% @end
%%--------------------------------------------------------------------
-spec start_link() -> {ok, pid()} | ignore | {error, term()}.
start_link() ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

register_lookup(IP, Score) ->
    gen_server:cast(?SERVER, {register_lookup, IP, Score}).

register_query_status(Status) ->
    gen_server:cast(?SERVER, {register_query_status, Status}).

reset_stat_table() ->
    gen_server:cast(?SERVER, reset_stat_table).

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================

%% @private
init([]) ->
    WhiteList = ets:new(?WHITELIST, [protected, named_table, {keypos, 1}]),
    StatTable = init_stat_table(),
    insert_ips(WhiteList, edge_core_config:whitelist()),
    ScoreTable = ets:new(?SCORE_TABLE, [protected, named_table, {keypos, 1}]),
    timer:send_after(1000, write_down_scoring),
    {ok, #state { score_table = ScoreTable,
                  whitelist   = WhiteList,
                  stat_table  = StatTable,
                  decay_rate  = edge_core_config:decay_rate()
                  }}.

%% @private
handle_call(_Request, _From, State) ->
    {reply, ok, State}.


handle_cast({register_query_status, Status}, State) ->
    ets:update_counter(?STAT_TABLE, Status, {2, 1}),
    {noreply, State};

%% @private
handle_cast({register_lookup, IP, Score}, State) ->
    % structure of rows {IP, BytesSend, BytesReceived}
    Default = {IP, 0},
    UpdateOps = [{2, Score}],
    Key = IP,
    ets:update_counter(?SCORE_TABLE, Key, UpdateOps, Default),
    {noreply, State};

handle_cast(reset_stat_table, State) ->
    true = ets:update_element(?STAT_TABLE, blocked, {2, 0}),
    true = ets:update_element(?STAT_TABLE, allowed, {2, 0}),
    true = ets:update_element(?STAT_TABLE, whitelisted, {2, 0}),
    {noreply, State};

handle_cast(_Msg, State) ->
    {noreply, State}.

%% @private
handle_info(write_down_scoring, #state { decay_rate  = DecayRate } = State) ->
    write_down_scoring(DecayRate),
    clean_scoring_table(),
    timer:send_after(1000, write_down_scoring),
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

write_down_scoring(DecayRate) ->
    Limit = 10000,
    done = write_down_scoring(ets:match(?SCORE_TABLE, '$1', Limit), DecayRate),
    lager:notice("Number of ip addresses in table after writedown: ~p", [length(ets:tab2list(?SCORE_TABLE))]).

write_down_scoring({Rows, Continuation}, DecayRate) ->
    UpdatedRows = lists:map(
                    fun ([{IP, Score}]) ->
                            NewScore = round(DecayRate * Score),
                            {IP, NewScore}
                    end, Rows),
    ets:insert(?SCORE_TABLE, UpdatedRows),
    write_down_scoring(ets:match(Continuation), DecayRate);

write_down_scoring('$end_of_table', _DecayRate) ->
    done.

clean_scoring_table() ->
    MatchSpec = ets:fun2ms(
        fun({_IP, Score})
              when Score < 100 -> true
        end),
    ets:select_delete(?SCORE_TABLE, MatchSpec).

insert_ips(Table, IPs) ->
    [ets:insert(Table, {IP}) || IP <- IPs].

init_stat_table() ->
    Table = ets:new(?STAT_TABLE, [protected, named_table, {keypos, 1}]),
    ets:insert(Table, {blocked, 0}),
    ets:insert(Table, {allowed, 0}),
    ets:insert(Table, {whitelisted, 0}),
    Table.
