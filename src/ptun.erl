%% Copyright (c) 2010-2011, Michael Santos <michael.santos@gmail.com>
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

%%
%% Example of using gen_icmp: Tunnel TCP data over ICMP
%%
%% Usage:
%% host1 (1.1.1.1) listens on 127.0.0.1:8787 and forwards data over ICMP
%%  to host2:
%% 
%% Args: Remote peer, local port
%% 
%% erl -noshell -pa ebin deps/*/ebin -eval 'ptun:server({2,2,2,2},8787)'
%%
%% host2 (2.2.2.2) receives ICMP echo requests and forwards the data
%%  to 127.0.0.1:22
%%
%% erl -noshell -pa ebin deps/*/ebin -eval 'ptun:client({1,1,1,1},22)'
%% 
%% Then, on host1: ssh -p 8787 127.0.0.1
%% 

-module(ptun).
-include_lib("pkt/include/pkt.hrl").

-export([client/2, server/2]).

-define(TIMEOUT, 5000).
-define(PORT, 8787).

-record(state, {
        addr,
        port,
        is,
        ts,
        id,
        seq = 1
    }).


server(Addr, Port) ->
    {ok, ICMP} = gen_icmp:open(),
    {ok, Socket} = gen_tcp:listen(Port, [
            binary,
            {packet, 0},
            {active, true},
            {reuseaddr, true},
            {ip, {127,0,0,1}}
        ]),
    accept(Addr, ICMP, Socket).

client(Addr, Port) ->
    {ok, ICMP} = gen_icmp:open(),
    State = #state{
        addr = Addr,
        port = Port,
        is = ICMP,
        id = crypto:rand_uniform(0, 16#FFFF)
    },
    proxy(State).

accept(Addr, ICMP, Listen) ->
    {ok, Socket} = gen_tcp:accept(Listen),
    gen_tcp:close(Listen),
    State = #state{
        addr = Addr,
        is = ICMP,
        ts = Socket,
        id = crypto:rand_uniform(0, 16#FFFF)
    },
    [{ok, Addr, _}] = gen_icmp:ping(ICMP, [Addr], [
            {id, State#state.id},
            {sequence, 0},
            {timeout, ?TIMEOUT}
        ]),
    proxy(State).

proxy(#state{
        is = IS,
        ts = TS,
        addr = Addr,
        port = Port
    } = State) ->
    receive
        % TCP socket events
        {tcp, TS, Data} ->
            Seq = send(Data, State),
            proxy(State#state{seq = Seq});
        {tcp_closed, TS} ->
            ok;
        {tcp_error, TS, Error} ->
            {error, Error};

        % ICMP socket events
        % client: open a connection on receiving the first ICMP ping
        {icmp, IS, Addr,
            <<?ICMP_ECHO:8, 0:8, _Checksum:16, _Id:16, Seq:16, _Data/binary>>}
            when TS == undefined, Seq == 0 ->
            {ok, Socket} = gen_tcp:connect("127.0.0.1", Port, [binary, {packet, 0}]),
            error_logger:info_report([{connect, {{127,0,0,1},Port}}]),
            proxy(State#state{ts = Socket});
        {icmp, IS, Addr,
            <<?ICMP_ECHO:8, 0:8, _Checksum:16, _Id:16, _Seq:16, Len:16, Data/binary>>} ->
            <<Data1:Len/bytes, _/binary>> = Data,
            ok = gen_tcp:send(TS, Data1),
            proxy(State#state{ts = TS});
        {icmp, IS, Addr, Packet} ->
            error_logger:info_report([{dropping, Packet}, {address, Addr}]),
            proxy(State)
    end.

% To keep it simple, we use 64 byte packets
% 4 bytes header, 2 bytes type, 2 bytes code, 2 bytes data length, 54 bytes data
send(<<Data:42/bytes, Rest/binary>>, #state{is = Socket, addr = Addr, id = Id, seq = Seq} = State) ->
    [{ok, Addr, _}] = gen_icmp:ping(Socket, [Addr], [
            {id, Id},
            {sequence, Seq},
            {timeout, ?TIMEOUT},
            {timestamp, false},
            {data, <<(byte_size(Data)):16, Data/bytes>>}
        ]),
    send(Rest, State#state{seq = Seq + 1});
send(Data, #state{is = Socket, addr = Addr, id = Id, seq = Seq}) ->
    Len = byte_size(Data),
    [{ok, Addr, _}] = gen_icmp:ping(Socket, [Addr], [
            {id, Id},
            {sequence, Seq},
            {timeout, ?TIMEOUT},
            {timestamp, false},
            {data, <<Len:16, Data/bytes, 0:((42-Len)*8)>>}
        ]),
    Seq+1.


