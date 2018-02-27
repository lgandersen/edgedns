%%%
%%% Copyright (c) 2016 Alexander Færøy. All rights reserved.
%%% Use of this source code is governed by a BSD-style
%%% license that can be found in the LICENSE file.
%%%
-module(edge_core_app).
-behaviour(application).

%% API.
-export([start/2, stop/1]).

-spec start(normal | {takeover, node()} | {failover, node()}, term()) -> {ok, pid()} | {error, term()}.
start(_Type, _Args) ->
    {ok, _} = edge_core_config:load_config(),
    edge_core_sup:start_link().

-spec stop([]) -> ok.
stop(_State) ->
    ok.
