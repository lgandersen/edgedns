%%%
%%% Copyright (c) 2016 Alexander Færøy. All rights reserved.
%%% Use of this source code is governed by a BSD-style
%%% license that can be found in the LICENSE file.
%%%
-module(edge_core_config).

%% API.
-export([port/0,
         active_message_count/0
        ]).

-spec port() -> inet:port_number().
port() ->
    get_value(port).

-spec active_message_count() -> non_neg_integer().
active_message_count() ->
    get_value(active_message_count).

%% @private
-spec get_value(Key) -> term()
    when
        Key :: atom().
get_value(Key) when is_atom(Key) ->
    {ok, Value} = application:get_env(edge_core, Key),
    Value.
