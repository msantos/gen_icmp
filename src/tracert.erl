%% Copyright (c) 2011, Michael Santos <michael.santos@gmail.com>
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

%%%
%%% traceroute
%%%
%%% Send a probe packet with the time to live set from 1. Monitor
%%% an ICMP socket for ICMP responses or timeout.
%%% 

-module(tracert).

-include("pkt.hrl").

-export([
        host/1, host/2,
        path/1
    ]).
-export([
        open/1,
        proplist_to_record/1,
        probe/1
    ]).

-record(state, {
        protocol = icmp,
        ttl = 1,
        max_hops = 31,
        timeout = 1000,         % 1 second

        packet,
        handler,
        dport = 0,
        sport = 0,
        next_port,

        saddr = {0,0,0,0},
        daddr,
        ws,
        rs
    }).


%%-------------------------------------------------------------------------
%%% API
%%-------------------------------------------------------------------------

open(Protocol0) ->
    {Protocol, Type} = case Protocol0 of
        icmp -> {icmp, raw};
        udp -> {udp, dgram};
        _ -> {raw, raw}
    end,

    {ok, Socket} = procket:open(0, [
        {family, inet},
        {type, Type},
        {protocol, Protocol}
    ]),

    {ok, Socket}.


host(Host) ->
    host(Host, []).

host(Host, Options) ->
    State = proplist_to_record(Options),

    % Write socket: probes
    {ok, WS} = open(State#state.protocol),

    % Read socket: ICMP trace
    {ok, RS} = gen_icmp:open(),

    Response = trace(State#state{
            daddr = gen_icmp:parse(Host),
            ws = WS,
            rs = RS
        }),

    gen_icmp:close(RS),
    ok = procket:close(WS),

    Response.


path(Path) when is_list(Path) ->
    [ begin
        case N of
            {Saddr, Microsec, {icmp, Packet}} ->
                ICMP = icmp_to_proplist(Packet),
                {Saddr, Microsec, ICMP};
            Any ->
                Any
        end
    end || N <- Path ].


%%-------------------------------------------------------------------------
%%% Probe and watch for the responses
%%-------------------------------------------------------------------------

%%
%% Send out probes and wait for the response
%%
trace(#state{handler = Handler} = State) when is_function(Handler) ->
    spawn_link(Handler),
    trace(State, []);
trace(State) ->
    trace(State, []).

% Traceroute complete
trace(#state{ttl = 0}, Acc) ->
    lists:reverse(Acc);
% Max hops reached
trace(#state{ttl = TTL, max_hops = TTL}, Acc) ->
    lists:reverse(Acc);
trace(#state{
        daddr = Daddr,
        rs = Socket,
        ttl = TTL,
        dport = Port,
        next_port = Next,
        timeout = Timeout
    } = State0, Acc) ->

    State = State0#state{dport = Next(Port)},
    ok = probe(State),

    Now = erlang:now(),

    receive
        % Response from destination
        {icmp, Socket, Daddr, Data} ->
            trace(
                State#state{ttl = 0},
                [{Daddr, timer:now_diff(erlang:now(), Now), {icmp, Data}}|Acc]
            );

        % Response from intermediate host
        {icmp, Socket, Saddr, Data} ->
            trace(
                State#state{ttl = TTL+1},
                [{Saddr, timer:now_diff(erlang:now(), Now), {icmp, Data}}|Acc]
            );

        % Response from protocol handler
        {tracert, Saddr, Data} ->
            trace(
                State#state{ttl = 0},
                [{Saddr, timer:now_diff(erlang:now(), Now), Data}|Acc]
            )
    after
        Timeout ->
            trace(
                State#state{ttl = TTL+1},
                [timeout|Acc]
            )
    end.


%%
%% Generates a probe packet
%%
probe(#state{
        packet = Fun,
        ws = Socket,
        saddr = {SA1,SA2,SA3,SA4},
        sport = Sport,
        daddr = {DA1,DA2,DA3,DA4},
        dport = Dport,
        ttl = TTL
    }) ->
    Sockaddr = <<
        (procket:sockaddr_common(?PF_INET, 16))/binary,
        Dport:16,                   % Destination Port
        DA1,DA2,DA3,DA4,            % IPv4 address
        0:64
    >>,
    ok = procket:setsockopt(Socket, ?IPPROTO_IP, ip_ttl(), <<TTL:32/native>>),
    Packet = Fun({{SA1,SA2,SA3,SA4}, Sport}, {{DA1,DA2,DA3,DA4}, Dport}, TTL),
    procket:sendto(Socket, Packet, 0, Sockaddr).
 

%%-------------------------------------------------------------------------
%%% Internal Functions
%%-------------------------------------------------------------------------
proplist_to_record(Options) ->
    Default = #state{},

    Protocol = proplists:get_value(protocol, Options, Default#state.protocol),
    Packet = proplists:get_value(packet, Options, protocol(Protocol)),
    Handler = proplists:get_value(handler, Options, Default#state.handler),

    Initial_ttl = proplists:get_value(ttl, Options, Default#state.ttl),
    Max_hops = proplists:get_value(max_hops, Options, Default#state.max_hops),
    Timeout = proplists:get_value(timeout, Options, Default#state.timeout),

    Saddr = proplists:get_value(saddr, Options, Default#state.saddr),
    Sport = proplists:get_value(sport, Options, crypto:rand_uniform(1,16#FFFF)),
    Dport = proplists:get_value(dport, Options, dport(Protocol)),

    Next_port = proplists:get_value(next_port, Options, next_port(Protocol)),

    #state{
        protocol = Protocol,
        packet = Packet,
        handler = Handler,
        ttl = Initial_ttl,
        max_hops = Max_hops,
        timeout = Timeout,
        saddr = Saddr,
        sport = Sport,

        dport = Dport,
        next_port = Next_port
    }.


icmp_to_proplist(ICMP) when is_binary(ICMP) ->
    {#icmp{type = Type,
        code = Code}, _Payload} = pkt:icmp(ICMP),
    {icmp, gen_icmp:code({Type,  Code})}.


%%
%% Construct the protocol headers for the probe
%%

% Default UDP packet
protocol(udp) ->
    fun({_Saddr, _Sport}, {_Daddr, _Dport}, _TTL) ->
        <<>>
    end;
% Default ICMP echo packet
protocol(icmp) ->
    fun({_Saddr, _Sport}, {_Daddr, _Dport}, _TTL) ->
        gen_icmp:packet([], <<(list_to_binary(lists:seq($\s, $W)))/binary>>)
    end.


%%
%% Calculate the port for different protocol types
%%
dport(udp) -> 1 bsl 15 + 666;
dport(icmp) -> 0.

next_port(udp) ->
    fun(N) -> N+1 end;
next_port(_) ->
    fun(N) -> N end.

ip_ttl() ->
    case os:type() of
        {unix, linux} -> 2;
        {unix, _} -> 4
    end.
