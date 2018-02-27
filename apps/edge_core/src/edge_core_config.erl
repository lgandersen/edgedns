%%%
%%% Copyright (c) 2016 Alexander Færøy. All rights reserved.
%%% Use of this source code is governed by a BSD-style
%%% license that can be found in the LICENSE file.
%%%
-module(edge_core_config).
-include_lib("kernel/include/file.hrl").

-define(CONFIGURE(Key, Value), application:set_env(edge_core, Key, Value, [{persistent, true}])).

%% API.
-export([listeners/0,
         blocking_threshold/0,
         active_message_count/0,
         port_range_resolvers/0,
         nameserver/0,
         decay_rate/0,
         enable_dampening/0,
         whitelist/0,
         silent/0,
         stats_log_frequency/0,
         load_config/0
        ]).

-spec enable_dampening() -> boolean().
enable_dampening() ->
    get_value(enable_dampening).

-spec listeners() -> inet:port_number().
listeners() ->
    Listeners = get_value(listeners),
    [{parse_address(Address), Port} || {Address, Port} <- Listeners].

-spec blocking_threshold() -> pos_integer().
blocking_threshold() ->
    get_value(blocking_threshold).

-spec decay_rate() -> float().
decay_rate() ->
    get_value(decay_rate).

-spec port_range_resolvers() -> {inet:port(), inet:port()}.
port_range_resolvers() ->
    get_value(port_range_resolvers).

-spec nameserver() -> {inet:ip(), inet:port()}.
nameserver() ->
    {AddressRaw, Port} = get_value(nameserver),
    {parse_address(AddressRaw), Port}.

-spec active_message_count() -> non_neg_integer().
active_message_count() ->
    get_value(active_message_count).

-spec silent() -> boolean().
silent() ->
    get_value(silent).

-spec whitelist() -> [inet:ip()].
whitelist() ->
    Whitelist = get_value(whitelist, []),
    [parse_address(Address) || Address <- Whitelist].

-spec stats_log_frequency() -> pos_integer().
stats_log_frequency() ->
    round(1000 * get_value(stats_log_frequency, 60)).


load_config() ->
    Fname = get_value(yaml_config_name, "edgedns_config.yml"),
    Paths = get_value(yaml_config_paths, []),
    Config = open_and_return(Paths, Fname),
    lists:map(fun parse_config/1, Config),
    application:ensure_all_started(lager).

%% @private
parse_config({"enable_dampening", Value}) ->
    ?CONFIGURE(enable_dampening, Value);

parse_config({"port_resolver_range",[{"start",Start},{"end",End}]}) ->
    ?CONFIGURE(port_range_resolvers, {Start, End});

parse_config({"silent", Value}) ->
    ?CONFIGURE(silent, Value);

parse_config({"blocking_threshold", Value}) ->
    ?CONFIGURE(blocking_threshold, Value);

parse_config({"decay_rate", Value}) ->
    ?CONFIGURE(decay_rate, Value);

parse_config({"whitelist", Value}) ->
    ?CONFIGURE(whitelist, Value);

parse_config({"stats_log_frequency", Value}) ->
    ?CONFIGURE(stats_log_frequency, Value);

parse_config({"stats_log_file", FileLocation}) ->
    Handlers = [
            {lager_console_backend, info}, %% Perhaps this should only be during testing
            {lager_file_backend, [
                {file, FileLocation},
                {level, '=notice'}
            ]}
        ],
    application:set_env(lager, handlers, Handlers, [{persistent, true}]);

parse_config({"active_message_count", Value}) ->
    ?CONFIGURE(active_message_count, Value);

parse_config({"listeners", Value}) ->
    Listeners = [{IP, Port} || [{"ip",IP}, {"port", Port}] <- Value],
    ?CONFIGURE(listeners, Listeners);

parse_config({"nameserver",[{"ip",IP},{"port",Port}]}) ->
    ?CONFIGURE(nameserver, {IP, Port});

parse_config(UnkownConfigurationParam) ->
    lager:warning("Did not understand what ~p is supposed to configure.", [UnkownConfigurationParam]).

%% @private
open_and_return([Path | Rest], Fname) ->
    File = filename:join([Path, Fname]),
    case file:read_file_info(File) of
        {error, enoent} ->
            open_and_return(Rest, Fname);

        {ok, _} ->
            [Config] = yamerl_constr:file(File),
            Config
    end;

open_and_return([], _Fname) ->
    [].

%% @private
-spec parse_address(string()) -> inet:ip().
parse_address(Address) ->
    IsItIPv4 = inet:getaddr(Address, inet),
    IsItIPv6 = inet:getaddr(Address, inet6),
    parse_address_(IsItIPv4, IsItIPv6).

parse_address_({ok, IPv4}, _) ->
    IPv4;

parse_address_(_, {ok, IPv6}) ->
    IPv6.


%% @private
-spec get_value(Key, Default) -> term()
    when
        Key     :: atom(),
        Default :: term().
get_value(Key, Default) when is_atom(Key) ->
    application:get_env(edge_core, Key, Default).

%% @private
-spec get_value(Key) -> term()
    when
        Key :: atom().
get_value(Key) when is_atom(Key) ->
    {ok, Value} = application:get_env(edge_core, Key),
    Value.
