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
         is_blocked/2
        ]).

%% gen_server callbacks
-export([init/1,
         handle_call/3,
         handle_cast/2,
         handle_info/2,
         terminate/2,
         code_change/3]).

-define(SERVER, ?MODULE).

-define(SCORE_TABLE, score_table).

-define(WHITELIST, whitelist).

-define(STAT_TABLE, stat_table).

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

is_blocked(IP, BlockingThreshold) ->
    ScoreLookup = ets:lookup(?SCORE_TABLE, IP),
    WhiteListed = ets:lookup(?WHITELIST, IP),
    case {ScoreLookup, WhiteListed} of
        {[], []} ->
            %% Allowed, not whitelisted
            register_query_status(allowed),
            false;

        {_, [{IP}]} ->
            %% Whitelisted and thus not blocked
            register_query_status(whitelisted),
            false;

        {[{IP, Score}], _} when Score > BlockingThreshold ->
            %% Ip is in the table and above threshold
            register_query_status(blocked),
            true;

        {[{IP, Score}], _} when Score =< BlockingThreshold ->
            %% Ip is in the table and below threshold
            register_query_status(allowed),
            false
    end.

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================

%% @private
init([]) ->
    WhiteList = ets:new(?WHITELIST, [protected, named_table, {keypos, 1}]),
    StatTable = init_stat_table(),
    insert_ips(WhiteList, edge_core_config:whitelist()),
    ScoreTable = ets:new(?SCORE_TABLE, [protected, named_table, {keypos, 1}]),
    timer:send_after(1000, write_down_points),
    {ok, #state { score_table = ScoreTable,
                  whitelist   = WhiteList,
                  stat_table  = StatTable,
                  decay_rate  = edge_core_config:decay_rate()
                  }}.

%% @private
handle_call(_Request, _From, State) ->
    {reply, ok, State}.


handle_cast({register_query_status, Status}, State) ->
    register_query_status_(Status),
    {noreply, State};

%% @private
handle_cast({register_lookup, IP, Score}, #state { score_table = Table } = State) ->
    % structure of rows {IP, BytesSend, BytesReceived}
    Default = {IP, 0},
    UpdateOps = [{2, Score}],
    Key = IP,
    ets:update_counter(Table, Key, UpdateOps, Default),
    {noreply, State};

handle_cast(_Msg, State) ->
    {noreply, State}.

%% @private
handle_info(write_down_points, #state { score_table = Table,
                                        decay_rate  = DecayRate } = State) ->
    write_down_points(Table, DecayRate),
    clean_up(Table),
    timer:send_after(1000, write_down_points),
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

write_down_points(Table, DecayRate) ->
    Limit = 10000,
    done = write_down_points(Table, ets:match(Table, '$1', Limit), DecayRate),
    lager:notice("Number of ip addresses in table after writedown: ~p", [length(ets:tab2list(Table))]).

write_down_points(Table, {Rows, Continuation}, DecayRate) ->
    UpdatedRows = lists:map(
                    fun ([{IP, Score}]) ->
                            NewScore = round(DecayRate * Score),
                            {IP, NewScore}
                    end, Rows),
    ets:insert(Table, UpdatedRows),
    write_down_points(Table, ets:match(Continuation), DecayRate);

write_down_points(_Table, '$end_of_table', _DecayRate) ->
    done.

clean_up(Table) ->
    MatchSpec = ets:fun2ms(
        fun({_IP, Score})
              when Score < 100 -> true
        end),
    ets:select_delete(Table, MatchSpec).

insert_ips(Table, IPs) ->
    [ets:insert(Table, {IP}) || IP <- IPs].

init_stat_table() ->
    Table = ets:new(?STAT_TABLE, [protected, named_table, {keypos, 1}]),
    ets:insert(Table, {blocked, 0}),
    ets:insert(Table, {allowed, 0}),
    ets:insert(Table, {whitelisted, 0}),
    Table.

register_query_status_(Status) ->
    ets:update_counter(?STAT_TABLE, Status, {2, 1}).
