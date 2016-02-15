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
-module(gen_icmp_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("kernel/include/inet.hrl").

-export([
        all/0
    ]).

-export([
        single_host/1,
        multiple_hosts/1,
        single_host_timeout/1,
        multiple_host_timeout/1,
        ipv4_all_addresses/1,
        reuse_socket/1,
        nxdomain/1,
        ipv4_set_ttl/1,
        ipv6_single_host/1,
        ipv6_multiple_hosts/1,
        ipv6_set_ttl/1,
        ipv6_filter_gen/1,
        ipv6_filter_get/1,
        ipv6_filter_all/1,
        ipv6_filter_echo/1
    ]).

all() ->
    [single_host, multiple_hosts, single_host_timeout, multiple_host_timeout,
        ipv4_all_addresses, reuse_socket, nxdomain, ipv4_set_ttl,
        ipv6_single_host, ipv6_multiple_hosts, ipv6_set_ttl, ipv6_filter_gen,
        ipv6_filter_get, ipv6_filter_all, ipv6_filter_echo].

single_host(_Config) ->
    [{ok,"www.google.com", {_,_,_,_}, {_,_,_,_}, {_,0,_,_},
                <<" !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJK">>}] = gen_icmp:ping("www.google.com").

% multiple hosts specified as strings and tuples, expect 2 responses
% only since we have a duplicate entries
multiple_hosts(_Config) ->
    [{ok,"www.google.com", {_,_,_,_}, {_,_,_,_}, {_,_,_,_}, <<" !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJK">>},
     {ok,{127,0,0,1}, {127,0,0,1}, {127,0,0,1}, {_,_,_,_}, <<" !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJK">>},
     {ok,"127.0.0.1", {127,0,0,1}, {127,0,0,1}, {_,_,_,_}, <<" !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJK">>}] =
    gen_icmp:ping(["www.google.com", {127,0,0,1}, "127.0.0.1"]).

single_host_timeout(_Config) ->
    [{error,timeout,"192.168.209.244",{192,168,209,244}}] = gen_icmp:ping("192.168.209.244", [{timeout, 5}]).

multiple_host_timeout(_Config) ->
    [{error,timeout,"192.168.147.147",{192,168,147,147}},
     {error,timeout,"192.168.209.244",{192,168,209,244}},
     {ok,"127.0.0.1",{127,0,0,1},{127,0,0,1}, {_,_,_,_}, <<" !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJK">>}] =
    gen_icmp:ping(["192.168.209.244", "127.0.0.1", "192.168.147.147"], [{timeout, 5}]).

ipv4_all_addresses(_Config) ->
    {ok, #hostent{h_addr_list = IPs}} = inet:gethostbyname("www.google.com", inet),
    Result = gen_icmp:ping("www.google.com", [{multi,true}]),
    N = length(IPs),
    N = length(Result).

% Order should be deterministic, since localhost will respond faster
% than a remote host
reuse_socket(_Config) ->
    {ok, Socket} = gen_icmp:open(),

    [{ok,"www.google.com",{_,_,_,_},{_,_,_,_}, {_,_,_,_}, <<" !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJK">>},
     {ok,"127.0.1.1",{127,0,1,1},{127,0,1,1}, {_,_,_,_}, <<" !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJK">>}] =
        gen_icmp:ping(Socket, ["127.0.1.1", "www.google.com"], []),

    [{ok,"www.google.com",{_,_,_,_},{_,_,_,_}, {_,_,_,_}, <<" !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJK">>},
     {ok,"127.0.1.1",{127,0,1,1},{127,0,1,1}, {_,_,_,_}, <<" !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJK">>}] =
        gen_icmp:ping(Socket, ["127.0.1.1", "www.google.com"], []),

    ok = gen_icmp:close(Socket).

% Hostname not resolveable
nxdomain(_Config) ->
    [{error,nxdomain,"unresolveable12345.notexist",undefined}] = gen_icmp:ping("unresolveable12345.notexist").

% Set the socket TTL
ipv4_set_ttl(_Config) ->
    [{error,timxceed_intrans,"www.google.com",
     {_,_,_,_},
     {_,_,_,_},
     {_,_,TTL,_},
     _}] = gen_icmp:ping("www.google.com", [{ttl, 1}]),
    true = TTL > 0.

ipv6_single_host(_Config) ->
    [{ok,"ipv6.google.com", {_,_,_,_,_,_,_,_},{_,_,_,_,_,_,_,_}, {_,0,_,_},
     <<" !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJK">>}] = gen_icmp:ping("ipv6.google.com", [inet6]).

ipv6_multiple_hosts(_Config) ->
    [{ok,"tunnelbroker.net",
     {_,_,_,_,_,_,_,_},
     {_,_,_,_,_,_,_,_},
     {_,_,_,_},
      <<" !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJK">>},
     {ok,"ipv6.google.com",
     {_,_,_,_,_,_,_,_},
     {_,_,_,_,_,_,_,_},
     {_,_,_,_}, <<" !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJK">>}] =
    gen_icmp:ping(["ipv6.google.com", "tunnelbroker.net"], [inet6]).

ipv6_different_request_reply_addresses() ->
    [{ok,"::",
     {0,0,0,0,0,0,0,0},
     {0,0,0,0,0,0,0,1},
     {_,0,_,_},
      <<" !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJK">>}] = gen_icmp:ping("::", [inet6]).

% Set the socket TTL
ipv6_set_ttl(_Config) ->
    [{error,unreach_net,"www.google.com",
     {_,_,_,_,_,_,_,_},
     {_,_,_,_,_,_,_,_},
     {_,_,_,_},
     _}] = gen_icmp:ping("www.google.com", [inet6, {ttl,1}]).

% ICMPv6 filter tests
ipv6_filter_gen(_Config) ->
    Filter = gen_icmp:icmp6_filter_setblockall(),

    true = gen_icmp:icmp6_filter_willblock(echo_request, Filter),
    false = gen_icmp:icmp6_filter_willpass(echo_request, Filter),

    Filter1 = gen_icmp:icmp6_filter_setpass(echo_request, Filter),
    Filter1 = gen_icmp:icmp6_filter_setpass(echo_request, Filter1),

    false = gen_icmp:icmp6_filter_willblock(echo_request, Filter1),
    true = gen_icmp:icmp6_filter_willpass(echo_request, Filter1),

    Filter = gen_icmp:icmp6_filter_setblock(echo_request, Filter1).

ipv6_filter_get(_Config) ->
    {ok, Socket} = gen_icmp:open([inet6]),

    Pass = gen_icmp:icmp6_filter_setpassall(),
    Block = gen_icmp:icmp6_filter_setblockall(),

    {ok, Pass} = gen_icmp:filter(Socket),

    ok = gen_icmp:filter(Socket, Block),
    {ok, Block} = gen_icmp:filter(Socket),

    ok = gen_icmp:close(Socket).

ipv6_filter_all(_Config) ->
    {ok, Socket} = gen_icmp:open([inet6]),

    Block = gen_icmp:icmp6_filter_setblockall(),

    [{error,timeout,"localhost",{0,0,0,0,0,0,0,1}}] =
        gen_icmp:ping(Socket, ["localhost"], [{timeout, 500}, {filter, Block}]),

    Pass = gen_icmp:icmp6_filter_setpassall(),

    [{ok,"localhost",
         {0,0,0,0,0,0,0,1},
         {0,0,0,0,0,0,0,1},
         _,
         _}] = gen_icmp:ping(
                 Socket,
                 ["localhost"],
                 [{timeout, 500}, {filter, Pass}]
                 ),

    ok = gen_icmp:close(Socket).

ipv6_filter_echo(_Config) ->
    {ok, Socket} = gen_icmp:open([inet6]),

    Block = gen_icmp:icmp6_filter_setblockall(),
    Filter = gen_icmp:icmp6_filter_setpass(echo_reply, Block),

    [{ok,"localhost",
         {0,0,0,0,0,0,0,1},
         {0,0,0,0,0,0,0,1},
         _,
         _}] = gen_icmp:ping(Socket, ["localhost"], [{timeout, 500}, {filter, Filter}]),

    ok = gen_icmp:close(Socket).
