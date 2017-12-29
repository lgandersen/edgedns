%%%
%%% Copyright (c) 2016 Alexander Færøy. All rights reserved.
%%% Use of this source code is governed by a BSD-style
%%% license that can be found in the LICENSE file.
%%%
%%%-------------------------------------------------------------------
%%% @author Alexander Færøy & Lasse Grinderslev Andersen
%%% @doc UDP Listener
%%%
%%% This server listens to incoming DNS requests, forwards them to
%%% the resolver processes and relay DNS repsonses back to right
%%% recipients.
%%%
%%% @end
%%%-------------------------------------------------------------------

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
          socket    :: gen_udp:socket(),
          active_n  :: non_neg_integer(),
          next_resolver :: non_neg_integer(),
          resolvers :: [pid()]
    }).

-include_lib("kernel/src/inet_dns.hrl").

-spec start_link() -> {ok, pid()} | ignore | {error, term()}.
start_link() ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

%% @private
init(_Args) ->
    Port   = edge_core_config:port(),
    Active = edge_core_config:active_message_count(),

    {DNSServerIP, DNSServerPort} = edge_core_config:nameserver(),

    %% Ports used to talk to the DNS server
    {ResolverPortStart, ResolverPortEnd} = edge_core_config:port_range_resolvers(),
    ConnectionPorts = lists:seq(ResolverPortStart, ResolverPortEnd),
    NResolvers = length(ConnectionPorts),

    %% Start our resolver processes that talks to the DNSServer
    ResolverPids = lists:map(
                  fun(LocalPort) ->
                          {ok, Pid} = edge_core_resolver:start_link(LocalPort, DNSServerIP, DNSServerPort),
                          Pid
                  end, ConnectionPorts),

    %% Make map to use for round robin distribution of queries to resolver processes
    Resolvers = maps:from_list(
                  lists:zip(
                    lists:seq(0, NResolvers - 1),
                    ResolverPids)),

    case gen_udp:open(Port, [binary, inet, {active, Active}, {reuseaddr, true}]) of
        {ok, Socket} ->
            lager:notice("Listening to incoming DNS requests on port ~p", [Port]),
            {ok, #state { resolvers     = Resolvers,
                          next_resolver = 0,
                          socket        = Socket,
                          active_n      = Active }};

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
handle_info({udp, _, IP, Port, Packet}, #state{resolvers = Resolvers, next_resolver = Resolver2Use} = StateData) ->
    %lager:warning("Incoming request: ~p", [IP]),
    Resolver = maps:get(Resolver2Use, Resolvers),
    edge_core_resolver:resolve(Resolver, IP, Port, Packet),
    NextResolverToUse = (Resolver2Use + 1) rem maps:size(Resolvers),
    {noreply, StateData#state { next_resolver = NextResolverToUse }};

handle_info({response_received, {_IP, _Port, _Response}}, #state { socket = _Socket } = State) ->
    % FIXME this is only while debugging. No need to send attack-traffic
    %lager:notice("Response received, relaying answer to client"),
    %gen_udp:send(Socket, IP, Port, Response),
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
