%%%
%%% Copyright (c) 2016 Alexander Færøy. All rights reserved.
%%% Use of this source code is governed by a BSD-style
%%% license that can be found in the LICENSE file.
%%%
-module(edge_core_udp_listener).
-behaviour(gen_server).

%% API.
-export([start_link/0]).

%% Generic Server Callbacks.
-export([init/1,
         handle_call/3,
         handle_cast/2,
         handle_info/2,
         terminate/2,
         code_change/3
        ]).

-define(SERVER, ?MODULE).

-record(state, {
          socket   :: gen_udp:socket(),
          active_n :: non_neg_integer()
    }).

-include_lib("kernel/src/inet_dns.hrl").

-spec start_link() -> {ok, pid()} | ignore | {error, term()}.
start_link() ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

%% @private
init(_Args) ->
    Port   = edge_core_config:port(),
    Active = edge_core_config:active_message_count(),
    case gen_udp:open(Port, [binary, inet, {active, Active}, {reuseaddr, true}]) of
        {ok, Socket} ->
            {ok, #state { socket   = Socket,
                          active_n = Active }};

        {error, _} = Error ->
            Error
    end.

%% @private
handle_call(Request, _From, State) ->
    lager:warning("Unhandled call: ~p", [Request]),
    {reply, unhandled, State}.

%% @private
handle_cast(Message, State) ->
    lager:warning("Unhandled cast: ~p", [Message]),
    {noreply, State}.

%% @private
handle_info({udp, _, IP, Port, Packet}, #state { socket = Socket } = State) ->
    case inet_dns:decode(Packet) of
        {ok, #dns_rec { header = #dns_header { id = ID } }= Data} ->

            case inet_res:resolve("foobar.com", in, a, [{nameservers, [ {{8,8,8,8}, 53} ]}]) of
                {ok, #dns_rec{ header = Header } = AResult} ->
                    Result = AResult#dns_rec{ header = Header#dns_header { id = ID } },
                    Response = inet_dns:encode(Result),
                    gen_udp:send(Socket, IP, Port, Response);

                _ -> ok
            end;

        {error, Reason} ->
            lager:warning("Unable to decode packet: ~p", [Reason])
    end,
    {noreply, State};

handle_info({udp_passive, _}, #state { socket = Socket, active_n = ActiveN } = State) ->
    inet:setopts(Socket, [{active, ActiveN}]),
    {noreply, State};

handle_info(Info, State) ->
    lager:warning("Unhandled info: ~p", [Info]),
    {noreply, State}.

%% @private
terminate(_Reason, _State) ->
    ok.

%% @private
code_change(_OldVersion, State, _Extra) ->
    {ok, State}.
