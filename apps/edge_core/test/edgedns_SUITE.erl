%%%-------------------------------------------------------------------
%%% @author lga
%%% @copyright (C) 2018, lga
%%% @doc
%%%
%%% @end
%%% Created : 2018-01-02 14:12:40.080561
%%%-------------------------------------------------------------------
-module(edgedns_SUITE).


%% API
-export([all/0,
         suite/0,
         groups/0,
         init_per_suite/1,
         end_per_suite/1,
         group/1,
         init_per_group/2,
         end_per_group/2,
         init_per_testcase/2,
         end_per_testcase/2]).

%% test cases
-export([
         %% TODO: test case names go here
         t_connectivity/1,
         t_edgedns_start_and_shutdown/1,
         t_edgedns/1,
         t_edgedns_whitelisted/1,
         t_edgedns_many_types/1,
         t_lookup_unicast/1,
         t_lookup_anycast/1
        ]).

-include_lib("common_test/include/ct.hrl").

-define(SET(List), sets:from_list(List)).
-define(EDGEDNS_CONFIG(Key, Value), application:set_env(edge_core, Key, Value)).

all() ->
    [
     %% TODO: Group names here e.g. {group, crud}
     %% Simple test of inet_res module and network io using google DNS
     {group, inet_res},

     %% Test that the censhipfree dns service works
     {group, censurfridns_dk},

     %% Actual tests of edgedns
     {group, edgedns}
    ].

suite() ->
    [{ct_hooks, [cth_surefire]}, {timetrap, {seconds, 30}}].

groups() ->
    [
        %% TODO: group definitions here e.g.
        %% {crud, [], [
        %%          t_create_resource,
        %%          t_read_resource,
        %%          t_update_resource,
        %%          t_delete_resource
        %%         ]}
        {inet_res, [], [t_connectivity]},
        {censurfridns_dk, [], [t_lookup_unicast, t_lookup_anycast]},
        {edgedns, [], [t_edgedns_start_and_shutdown,
                       t_edgedns,
                       t_edgedns_whitelisted,
                       t_edgedns_many_types]}
    ].

%%%===================================================================
%%% Overall setup/teardown
%%%===================================================================
init_per_suite(Config) ->
    lager:start(),
    [{unicast_server, {{89, 233, 43, 71}, 53}},
     {anycast_server, {{91, 239, 100, 100}, 53}},
     {google_server, {{8, 8, 8, 8}, 53}},
     {edgedns_server, {{127, 0, 0, 1}, 5331}},
     {edgedns_config, none}
     | Config].

end_per_suite(_Config) ->
    ok.


%%%===================================================================
%%% Group specific setup/teardown
%%%===================================================================
group(_Groupname) ->
    [].

init_per_group(edgedns, Config) ->
    Config;

init_per_group(_Groupname, Config) ->
    Config.

end_per_group(_Groupname, _Config) ->

    ok.


%%%===================================================================
%%% Testcase specific setup/teardown
%%%===================================================================
init_per_testcase(_TestCase, Config) ->
    Config.

end_per_testcase(_TestCase, _Config) ->
    ok.

%%%===================================================================
%%% Individual Test Cases (from groups() definition)
%%%===================================================================
t_connectivity(Config) ->
    DNSServer = ?config(google_server, Config),
    ok = run_test_queries(DNSServer).

t_lookup_unicast(Config) ->
    DNSServer = ?config(unicast_server, Config),
    ok = run_test_queries(DNSServer).

t_lookup_anycast(Config) ->
    DNSServer = ?config(anycast_server, Config),
    ok = run_test_queries(DNSServer).

t_edgedns_start_and_shutdown(_Config) ->
    ok = set_env_variables(),
    Pids = start_edgedns_processes(),
    shutdown_edgedns_processe(Pids).

t_edgedns(Config) ->
    ok = set_env_variables(),
    _ = start_edgedns_processes(),
    DNSServer = ?config(edgedns_server, Config),
    ok = run_test_queries(DNSServer),
    ok.

t_edgedns_whitelisted(Config) ->
    ok = set_env_variables([{whitelisted, ["127.0.0.1"]}]),
    _ = start_edgedns_processes(),
    DNSServer = ?config(edgedns_server, Config),
    ok = run_test_queries(DNSServer),
    ok.

%% FIXME make test da is being blocked

t_edgedns_many_types(Config) ->
    ok = set_env_variables(),
    _ = start_edgedns_processes(),
    Types = [a, aaaa, ns, mx, txt],
    lists:map(fun(Type) -> verify_dns_response(Config, Type) end, Types),
    ok.

verify_dns_response(Config, Type) ->
    EdgeDNS = ?config(edgedns_server, Config),
    TestServer = ?config(unicast_server, Config),
    {ok, {dns_rec, _Header1, QDList1, ANList1, NSList1, ARList1}} = inet_res:resolve("bornhack.dk", in, Type, [{nameservers, [EdgeDNS]}]),
    {ok, {dns_rec, _Header2, QDList2, ANList2, NSList2, ARList2}} = inet_res:resolve("bornhack.dk", in, Type, [{nameservers, [TestServer]}]),
    true = ?SET(QDList1) =:= ?SET(QDList2),
    true = ?SET(ANList1) =:= ?SET(ANList2),
    true = ?SET(NSList1) =:= ?SET(NSList2),
    true = ?SET(ARList1) =:= ?SET(ARList2),
    ok.


set_env_variables() ->
    set_env_variables([]).

set_env_variables(Options) ->
    DefaultOptions = [
    {listeners,            [{"127.0.0.1", 5331}]},
    {silent,               false},
    {port_range_resolvers, {5333, 5340}},
    {nameserver,           {{89, 233, 43, 71}, 53}},
    {active_message_count, 10},
    {blocking_threshold,   99999999999},
    {decay_rate,           0.5},
    {do_nothing,           false},
    {whitelist,            []}  % Seperate test with and without being whitelisted!
                     ],
    lists:foreach(fun({Key, DefaultValue}) ->
                          Value = proplists:get_value(Key, Options, DefaultValue),
                          ?EDGEDNS_CONFIG(Key, Value)
                  end, DefaultOptions).

start_edgedns_processes() ->
    {ok, Listener} = edge_core_udp_listener:start_link(),
    {ok, Logger} = edge_core_traffic_logger:start_link(),
    {ok, Monitor} = edge_core_traffic_monitor:start_link(),
    {Listener, Logger, Monitor}.

shutdown_edgedns_processe({Listener, Logger, Monitor}) ->
    exit(Listener, normal),
    exit(Logger, normal),
    exit(Monitor, normal).

run_test_queries(DNSServer) ->
    AmazonDotCom = sets:from_list([{205,251,242,103}, {176,32,98,166}, {176,32,103,205}]),
    BornhackDotDk = [{85,235,250,91}],
    NonExistingDomain = [],

    BornhackDotDk = inet_res:lookup("bornhack.dk", in, a, [{nameservers, [DNSServer]}]),
    AmazonDotCom = sets:from_list(inet_res:lookup("amazon.com", in, a, [{nameservers, [DNSServer]}])),
    NonExistingDomain = inet_res:lookup("ido.notexist", in, a, [{nameservers, [DNSServer]}]),
    ok.
