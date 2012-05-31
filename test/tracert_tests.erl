%% Copyright (c) 2012, Michael Santos <michael.santos@gmail.com>
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
-module(tracert_tests).

-compile(export_all).

-include_lib("eunit/include/eunit.hrl").


traceroute_localhost_test() ->
    Path = tracert:host("127.0.0.1"),

    [{{127,0,0,1},
     _,
     {icmp,_}}] = Path,

    [{{127,0,0,1},_,echo}] = tracert:path(Path).

traceroute_udp_localhost_test() ->
    Path = tracert:host("127.0.0.1", [{protocol, udp}]),

    [{{127,0,0,1},
     _,
     {icmp,_}}] = Path,

    [{{127,0,0,1}, _, unreach_port}] = tracert:path(Path).

traceroute_multiple_hops_test() ->
    Path = tracert:host({8,8,8,8}),
    true = is_list(tracert:path(Path)).

traceroute_resolv_multiple_addresses_test() ->
    Path = tracert:host("google.com"),
    [{_,_,echoreply} | _] = lists:reverse(tracert:path(Path)).

traceroute_resolv_single_address_test() ->
    Path = tracert:host("erlang.org"),
    [{_,_,echoreply} | _] = lists:reverse(tracert:path(Path)).

% Naming for type/code in ICMPv6 differs from ICMP
traceroute_ipv6_resolv_icmp_test() ->
    Path = tracert:host("ipv6.google.com", [inet6]),
    [{_,_,echo_reply} | _] = lists:reverse(tracert:path(Path)).

traceroute_ipv6_resolv_udp_test() ->
    Path = tracert:host("ipv6.google.com", [inet6, {protocol, udp}]),
    [{_,_,dst_unreach_noport} | _] = lists:reverse(tracert:path(Path)).

traceroute_timeout_test() ->
    [timeout] = tracert:host({255,255,255,254}, [
                {ttl, 1}, {max_hops, 2}, {timeout, 5}
                ]).
