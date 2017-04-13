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

-define(STATS_TABLE, traffic_stats).

-include_lib("stdlib/include/ms_transform.hrl").

-record(state, {traffic_stats      :: ets:tid(),
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

is_blocked(IP, BlockingThreshold) ->
    case ets:lookup(?STATS_TABLE, IP) of
        [] ->
            %lager:warning("IP ~p not found in traffic stats table", [IP]),
            false;

        [{IP, Score}] ->
            %% If the IP is in the table, check if its score is above the blocking threshold or not
            %lager:notice("IP Found in traffic stats table, having ~p points", [round(Score)]),
            Score > BlockingThreshold
    end.

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================

%% @private
init([]) ->
    TrafficStats = ets:new(?STATS_TABLE, [protected, named_table, {keypos, 1}]),
    timer:send_after(1000, write_down_points),
    {ok, #state { traffic_stats       = TrafficStats,
                  decay_rate          = edge_core_config:decay_rate()
                  }}.

%% @private
handle_call(_Request, _From, State) ->
    {reply, ok, State}.


%% @private
handle_cast({register_lookup, IP, Score}, #state { traffic_stats = Table } = State) ->
    % structure of rows {IP, BytesSend, BytesReceived}
    Default = {IP, 0},
    UpdateOps = [{2, Score}],
    Key = IP,
    ets:update_counter(Table, Key, UpdateOps, Default),
    %lager:notice("Traffic stats so far: ~p", [ets:tab2list(Table)]),
    {noreply, State};

handle_cast(_Msg, State) ->
    {noreply, State}.

%% @private
handle_info(write_down_points, #state { traffic_stats = TrafficStats,
                                        decay_rate    = DecayRate } = State) ->
    write_down_points(TrafficStats, DecayRate),
    clean_up(TrafficStats),
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
              %% "," means 'and' and ";" means 'or' in guard expressions
              when Score < 100 -> true
        end),
    ets:select_delete(Table, MatchSpec).
