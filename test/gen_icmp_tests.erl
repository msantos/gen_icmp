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
-module(gen_icmp_tests).

-compile(export_all).

-include_lib("eunit/include/eunit.hrl").


single_host_ok_test() ->
    [{ok,"www.google.com", {_,_,_,_},
            {{_,_,_},
                <<" !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJK">>}}] = gen_icmp:ping("www.google.com").

% multiple hosts specified as strings and tuples, expect 2 responses
% only since we have a duplicate entries
multiple_hosts_ok_test() ->
    [{ok,"www.google.com", {_,_,_,_}, {{_,_,_}, <<" !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJK">>}},
     {ok,{127,0,0,1}, {127,0,0,1}, {{_,_,_}, <<" !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJK">>}}] =
    gen_icmp:ping(["www.google.com", {127,0,0,1}, "127.0.0.1"]).

multiple_hosts_no_dedup_ok_test() ->
    [{ok,"www.google.com", {_,_,_,_}, {{_,_,_}, <<" !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJK">>}},
     {ok,"127.0.0.1", {127,0,0,1}, {{_,_,_}, <<" !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJK">>}},
     {ok,{127,0,0,1}, {127,0,0,1}, {{_,_,_}, <<" !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJK">>}}] =
    gen_icmp:ping(["www.google.com", {127,0,0,1}, "127.0.0.1"], [{dedup, false}]).

single_host_timeout_test() ->
    [{{error,timeout},"192.168.209.244",{192,168,209,244}}] = gen_icmp:ping("192.168.209.244", [{timeout, 5}]).

multiple_host_timeout_test() ->
    [{{error,timeout},"192.168.147.147",{192,168,147,147}},
     {{error,timeout},"192.168.209.244",{192,168,209,244}},
     {ok,"127.0.0.1",{127,0,0,1}, {{_,_,_}, <<" !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJK">>}}] =
    gen_icmp:ping(["192.168.209.244", "127.0.0.1", "192.168.147.147"], [{timeout, 5}]).

% Order should be deterministic, since localhost will respond faster
% than a remote host
reuse_socket_test() ->
    {ok, Socket} = gen_icmp:open(),

    [{ok,"www.google.com",{_,_,_,_}, {{_,_,_}, <<" !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJK">>}},
     {ok,"127.0.1.1",{127,0,1,1}, {{_,_,_}, <<" !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJK">>}}] =
        gen_icmp:ping(Socket, ["127.0.1.1", "www.google.com"], []),

    [{ok,"www.google.com",{_,_,_,_}, {{_,_,_}, <<" !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJK">>}},
     {ok,"127.0.1.1",{127,0,1,1}, {{_,_,_}, <<" !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJK">>}}] =
        gen_icmp:ping(Socket, ["127.0.1.1", "www.google.com"], []),

    ok = gen_icmp:close(Socket).

traceroute_localhost_test() ->
    Path = tracert:host("127.0.0.1"),

    [{{127,0,0,1},
     _,
     {icmp,_}}] = Path,

    [{{127,0,0,1},_,echo}] = tracert:path(Path).

traceroute_multiple_hops_test() ->
    Path = tracert:host({8,8,8,8}),
    true = is_list(tracert:path(Path)).
