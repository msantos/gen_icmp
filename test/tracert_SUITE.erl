%% Copyright (c) 2012-2016, Michael Santos <michael.santos@gmail.com>
%% All rights reserved.
%%
%% Redistribution and use in source and binary forms, with or without
%% modification, are permitted provided that the following conditions
%% are met:
%%
%% Redistributions of source code must retain the above copyright
%% notice, this list of conditions and the following disclaimer.
%%
%% Redistributions in binary form must reproduce the above copyright
%% notice, this list of conditions and the following disclaimer in the
%% documentation and/or other materials provided with the distribution.
%%
%% Neither the name of the author nor the names of its contributors
%% may be used to endorse or promote products derived from this software
%% without specific prior written permission.
%%
%% THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
%% "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
%% LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
%% FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
%% COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
%% INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
%% BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
%% LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
%% CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
%% LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
%% ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
%% POSSIBILITY OF SUCH DAMAGE.
-module(tracert_SUITE).

-include_lib("common_test/include/ct.hrl").

-export([
    all/0
]).

-export([
    traceroute_localhost/1,
    traceroute_udp_localhost/1,
    traceroute_multiple_hops/1,
    traceroute_resolv_multiple_addresses/1,
    traceroute_resolv_single_address/1,
    traceroute_ipv6_resolv_icmp/1,
    traceroute_ipv6_resolv_udp/1,
    traceroute_timeout/1,
    traceroute_nxdomain/1
]).

all() ->
    [
        traceroute_localhost,
        traceroute_udp_localhost,
        traceroute_multiple_hops,
        traceroute_resolv_multiple_addresses,
        traceroute_resolv_single_address,
        traceroute_ipv6_resolv_icmp,
        traceroute_ipv6_resolv_udp,
        traceroute_timeout,
        traceroute_nxdomain
    ].

traceroute_localhost(_Config) ->
    Path = tracert:host("127.0.0.1"),

    [{{127, 0, 0, 1}, _, {icmp, _}}] = Path,

    [{{127, 0, 0, 1}, _, echo}] = tracert:path(Path).

traceroute_udp_localhost(_Config) ->
    Path = tracert:host("127.0.0.1", [{protocol, udp}]),

    [{{127, 0, 0, 1}, _, {icmp, _}}] = Path,

    [{{127, 0, 0, 1}, _, unreach_port}] = tracert:path(Path).

traceroute_multiple_hops(_Config) ->
    Path = tracert:host({8, 8, 8, 8}),
    true = is_list(tracert:path(Path)).

traceroute_resolv_multiple_addresses(_Config) ->
    Path = tracert:host("google.com"),
    [{_, _, echoreply} | _] = lists:reverse(tracert:path(Path)).

traceroute_resolv_single_address(_Config) ->
    Path = tracert:host("erlang.org"),
    [{_, _, echoreply} | _] = lists:reverse(tracert:path(Path)).

% Naming for type/code in ICMPv6 differs from ICMP
traceroute_ipv6_resolv_icmp(_Config) ->
    Path = tracert:host("ipv6.google.com", [inet6]),
    [{_, _, echo_reply} | _] = lists:reverse(tracert:path(Path)).

traceroute_ipv6_resolv_udp(_Config) ->
    Path = tracert:host("ipv6.google.com", [inet6, {protocol, udp}]),
    [{_, _, dst_unreach_noport} | _] = lists:reverse(tracert:path(Path)).

traceroute_timeout(_Config) ->
    [timeout] = tracert:host({255, 255, 255, 254}, [
        {ttl, 1}, {max_hops, 2}, {timeout, 5}
    ]).

traceroute_nxdomain(_Config) ->
    {'EXIT', {{badmatch, {error, nxdomain}}, _}} =
        (catch tracert:host("unresolveable12345.notexist")),
    ok.
