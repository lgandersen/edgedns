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
         t_connectivity/1,
         t_lookup_unicast/1,
         t_lookup_anycast/1,
         t_edgedns_start_and_shutdown/1,
         t_edgedns_a/1,
         t_edgedns_aaaa/1,
         t_edgedns_ns/1,
         t_edgedns_mx/1,
         t_edgedns_txt/1,
         t_edgedns_many_ips/1,
         t_edgedns_nonexisting_domain/1,
         t_edgedns_blocked/1,
         t_edgedns_unblocked/1,
         t_edgedns_whitelisted/1,
         t_edgedns_stats_log_test/1
        ]).

-include_lib("common_test/include/ct.hrl").
-include_lib("test_queries.hrl").

-define(DUMMY_DNS_SERVER, {{127, 0, 0, 1}, 8538}).
-define(SET(List), sets:from_list(List)).
-define(EDGEDNS_CONFIG(Key, Value), application:set_env(edge_core, Key, Value)).
-define(BORNHACK_A_LOOKUP(DNSServer), [{85,235,250,91}] = inet_res:lookup("bornhack.dk", in, a, [{nameservers, [DNSServer]}])).

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
                       t_edgedns_a,
                       t_edgedns_aaaa,
                       t_edgedns_ns,
                       t_edgedns_mx,
                       t_edgedns_txt,
                       t_edgedns_many_ips,
                       t_edgedns_nonexisting_domain,
                       t_edgedns_blocked,
                       t_edgedns_unblocked
                      ]}
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

t_edgedns_a(_Config) ->
    ok = resolve_and_verify("bornhack.dk", a).

t_edgedns_aaaa(_Config) ->
    ok = resolve_and_verify("bornhack.dk", aaaa).

t_edgedns_ns(_Config) ->
    ok = resolve_and_verify("bornhack.dk", ns).

t_edgedns_mx(_Config) ->
    ok = resolve_and_verify("bornhack.dk", mx).

t_edgedns_txt(_Config) ->
    ok = resolve_and_verify("bornhack.dk", mx).

t_edgedns_many_ips(_Config) ->
    ok = resolve_and_verify("amazon.com", a).

t_edgedns_nonexisting_domain(_Config) ->
    ok = resolve_and_verify("ido.notexist", a).

t_edgedns_blocked(_Config) ->
    init_edgedns_and_dummydns([{blocking_threshold, 10}]),
    edge_dns_lookup("bornhack.dk", a),
    timer:sleep(1000),
    LastLine = get_last_line("log/stats.log"),
    {_start, _end} = binary:match(LastLine, <<"dampening activated.">>),
    ok.

t_edgedns_unblocked(_Config) ->
    init_edgedns_and_dummydns([{blocking_threshold, 2000},
                               {decay_rate, 0.50},
                               {whitelist, ["127.0.0.1"]}]),
    edge_dns_lookup("bornhack.dk", a),
    timer:sleep(2000),
    LastLine = get_last_line("log/stats.log"),
    {_start, _end} = binary:match(LastLine, <<"dampening removed.">>),
    ok.

t_edgedns_whitelisted(_Config) ->
    ok = set_env_variables([{blocking_threshold, 10},
                            {whitelist, ["127.0.0.1"]}]),
    _ = start_edgedns_processes(),
    edge_dns_lookup("bornhack.dk", a),
    edge_dns_lookup("amazon.com", a),
    edge_dns_lookup("ido.notexist", a),
    ok.

t_edgedns_stats_log_test(_Config) ->
    %% Aproximate score of this query (a bornhack.dk) is 3000.
    %% FIXME not done.
    Query = <<0,1,1,0,0,1,0,0,0,0,0,0,8,98,111,114,110,104,97,99,107,2,100,107,0,0,1,0,1>>,
    ok = set_env_variables([{blocking_threshold, 4000},
                            {silent, true},
                            {decay_rate, 0.99},
                            {stats_log_frequencey, 1},
                            {whitelist, ["127.0.0.1", "13.37.13.37"]}]),
    {Listener, _Logger, _Monitor} = start_edgedns_processes(),
    Listener ! {udp, no_socket, {127,0,0,1}, no_port, Query},
    Listener ! {udp, no_socket, {127,0,0,1}, no_port, Query},
    Listener ! {udp, no_socket, {127,0,0,1}, no_port, Query},
    Listener ! {udp, no_socket, {10,0,13,37}, no_port, Query},
    Listener ! {udp, no_socket, {10,0,13,37}, no_port, Query},
    timer:sleep(2000),
    ok.

%%===================================================================
%% Internal functions
%%===================================================================
%% @private
start_dummy_dns_server() ->
    {IP, Port} = edge_core_config:nameserver(),
    Requests2Response = #{
     ?BORNHACK_A_REQUEST    => ?BORNHACK_A_RESPONSE,
     ?BORNHACK_AAAA_REQUEST => ?BORNHACK_AAAA_RESPONSE,
     ?BORNHACK_NS_REQUEST   => ?BORNHACK_NS_RESPONSE,
     ?BORNHACK_MX_REQUEST   => ?BORNHACK_MX_RESPONSE,
     ?BORNHACK_TXT_REQUEST  => ?BORNHACK_TXT_RESPONSE,
     ?BORNHACK_A_REQUEST    => ?BORNHACK_A_RESPONSE,
     ?AMAZON_A_REQUEST      => ?AMAZON_A_RESPONSE,
     ?DO_NOT_EXIST_REQUEST  => ?DO_NOT_EXIST_RESPONSE
     },
    Opts = [binary, inet, {ip, IP}, {active, true}, {reuseaddr, true}],
    case gen_udp:open(Port, Opts) of
        {ok, _Socket} ->
            dummy_dns_server(Requests2Response);

        {error, _} = Error ->
            Error
    end.

dummy_dns_server(Requests2Response) ->
    receive
        {udp, Socket, IP, InPortNo, Packet} ->
            <<Id:2/binary, Request/binary>> = Packet,
            Response = maps:get(Request, Requests2Response),
            gen_udp:send(Socket, IP, InPortNo, <<Id:2/binary, Response/binary>>),
            dummy_dns_server(Requests2Response)
    end.


%% @private
get_last_line(FilePath) ->
    {ok, LogRaw} = file:read_file(FilePath),
    [_, LastLine | _Rest] = lists:reverse(binary:split(LogRaw, <<"\n">>, [global])),
    LastLine.

%% @private
verify_dns_response(Response, ExpectedResponse) ->
    {dns_rec, Header1, QDList1, ANList1, NSList1, ARList1} = Response,
    {dns_rec, Header2, QDList2, ANList2, NSList2, ARList2} = ExpectedResponse,
    verify_header(Header1, Header2),
    true = ?SET(QDList1) =:= ?SET(QDList2),
    true = ?SET(ANList1) =:= ?SET(ANList2),
    true = ?SET(NSList1) =:= ?SET(NSList2),
    true = ?SET(ARList1) =:= ?SET(ARList2),
    ok.

verify_header(Header, ExpectedHeader) ->
    {dns_header,_Id1,A,B,C,D,E,F,G,H} = Header,
    {dns_header,_Id2,A,B,C,D,E,F,G,H} = ExpectedHeader,
    ok.

%% @private
resolve_and_verify(Domain, Type) ->
    ok = init_edgedns_and_dummydns(),
    [EdgeDNS]= edge_core_config:listeners(),
    DummyDNS = edge_core_config:nameserver(),
    {Status, ParsedResponse1} = inet_res:resolve(Domain, in, Type, [{nameservers, [EdgeDNS]}]),
    {Status, ParsedResponse2} = inet_res:resolve(Domain, in, Type, [{nameservers, [DummyDNS]}]),
    case Status of
        ok ->
            verify_dns_response(ParsedResponse1, ParsedResponse2);

        error ->
            {nxdomain, ParsedResponse1_} = ParsedResponse1,
            {nxdomain, ParsedResponse2_} = ParsedResponse2,
            verify_dns_response(ParsedResponse1_, ParsedResponse2_)
    end,
    ok.


%% @private
edge_dns_lookup(Domain, Type) ->
    [{IP, Port}] = edge_core_config:listeners(),
    inet_res:resolve(Domain, in, Type, [{nameservers, [{IP, Port}]}]).

%% @private
init_edgedns_and_dummydns() ->
    init_edgedns_and_dummydns([]).

init_edgedns_and_dummydns(EdgeDNSOpts) ->
    ok = set_env_variables(EdgeDNSOpts),
    spawn_link(fun () -> start_dummy_dns_server() end),
    _ = start_edgedns_processes(),
    ok.

%% @private
set_env_variables() ->
    set_env_variables([]).

set_env_variables(Options) ->
    lists:foreach(
      fun({Key, Value}) ->
              ?EDGEDNS_CONFIG(Key, Value)
      end, Options).

%% @private
start_edgedns_processes() ->
    {ok, Listener} = edge_core_udp_listener:start_link(),
    {ok, Logger} = edge_core_traffic_logger:start_link(),
    {ok, Monitor} = edge_core_traffic_monitor:start_link(),
    {Listener, Logger, Monitor}.

%% @private
shutdown_edgedns_processe({Listener, Logger, Monitor}) ->
    exit(Listener, normal),
    exit(Logger, normal),
    exit(Monitor, normal).

%% @private
run_test_queries(DNSServer) ->
    AmazonDotCom = sets:from_list([{205,251,242,103}, {176,32,98,166}, {176,32,103,205}]),
    BornhackDotDk = [{85,235,250,91}],
    NonExistingDomain = [],

    BornhackDotDk = inet_res:lookup("bornhack.dk", in, a, [{nameservers, [DNSServer]}]),
    AmazonDotCom = sets:from_list(inet_res:lookup("amazon.com", in, a, [{nameservers, [DNSServer]}])),
    NonExistingDomain = inet_res:lookup("ido.notexist", in, a, [{nameservers, [DNSServer]}]),
    ok.
