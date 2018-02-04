%%%
%%% Copyright (c) 2016 Alexander Færøy. All rights reserved.
%%% Use of this source code is governed by a BSD-style
%%% license that can be found in the LICENSE file.
%%%
-module(edge_core_config).

%% API.
-export([listeners/0,
         blocking_threshold/0,
         active_message_count/0,
         port_range_resolvers/0,
         nameserver/0,
         decay_rate/0,
         no_blocking/0,
         whitelist/0,
         silent/0,
         query_log/0,
         stats_log/0,
         stats_log_frequencey/0
        ]).

-spec no_blocking() -> boolean().
no_blocking() ->
    get_value(no_blocking).

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
    Whitelist = get_value(whitelist),
    [parse_address(Address) || Address <- Whitelist].

-spec query_log() -> string().
query_log() ->
    get_value(query_log, no_file).

-spec stats_log() -> string().
stats_log() ->
    get_value(stats_log, no_file).

-spec stats_log_frequencey() -> pos_integer().
stats_log_frequencey() ->
    1000 * get_value(stats_log_frequencey, 60).

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
