%%%
%%% Copyright (c) 2016 Alexander Færøy. All rights reserved.
%%% Use of this source code is governed by a BSD-style
%%% license that can be found in the LICENSE file.
%%%
-module(edge_core_config).

%% API.
-export([port/0,
         blocking_threshold/0,
         active_message_count/0,
         port_range_resolvers/0,
         nameserver/0,
         decay_rate/0,
         do_nothing/0,
         silent/0
        ]).

-spec do_nothing() -> boolean().
do_nothing() ->
    get_value(do_nothing).

-spec port() -> inet:port_number().
port() ->
    get_value(port).

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
    get_value(nameserver).

-spec active_message_count() -> non_neg_integer().
active_message_count() ->
    get_value(active_message_count).

-spec silent() -> boolean().
silent() ->
    get_value(silent).

%% @private
-spec get_value(Key) -> term()
    when
        Key :: atom().
get_value(Key) when is_atom(Key) ->
    {ok, Value} = application:get_env(edge_core, Key),
    Value.
