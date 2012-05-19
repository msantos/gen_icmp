%% Copyright (c) 2011-2012, Michael Santos <michael.santos@gmail.com>
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
-behaviour(gen_server).

-include_lib("pkt/include/pkt.hrl").

-export([
        host/1, host/2, host/3,
        path/1
    ]).
-export([
        open/0, open/1,
        close/1,
        socket/3, socket/4,
        proplist_to_record/1,
        probe/5,
        response/1
    ]).

-export([start_link/1]).
%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
        terminate/2, code_change/3]).


-record(state, {
        pid,

        protocol = icmp,
        ttl = 1,
        max_hops = 31,
        timeout = 1000,         % 1 second
        setuid = true,

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
host(Host) ->
    host(Host, []).

host(Host, Options) ->
    {ok, Socket} = open(Options),
    Path = host(Socket, Host, Options),
    close(Socket),
    Path.

host(Ref, Host, Options) ->
    {ok, _, [Daddr|_]} = gen_icmp:parse(Host),
    State = proplist_to_record(Options),
    ok = gen_server:call(Ref, {handler, State#state.handler}, infinity),
    trace(Ref, State#state{daddr = Daddr}).


trace(Ref, State) ->
    flush_events(Ref),
    Sport = gen_server:call(Ref, sport),
    Path = trace(Ref, State#state{sport = Sport}, []),
    flush_events(Ref),
    Path.

% Traceroute complete
trace(_Ref, #state{ttl = 0}, Acc) ->
    lists:reverse(Acc);
% Max hops reached
trace(_Ref, #state{ttl = TTL, max_hops = TTL}, Acc) ->
    lists:reverse(Acc);
trace(Ref,
    #state{
        daddr = Daddr,
        dport = Dport,

        saddr = Saddr,
        sport = Sport,

        ttl = TTL,
        packet = Fun,
        next_port = Next,

        timeout = Timeout
    } = State0, Acc) ->

    State = State0#state{dport = Next(Dport)},
    Packet = Fun({Saddr, Sport}, {Daddr, Dport}, TTL),
    ok = probe(Ref, Daddr, Dport, TTL, Packet),

    Now = erlang:now(),

    receive
        % Response from destination
        {icmp, Ref, Daddr, {_, Data}} ->
            trace(Ref, State#state{ttl = 0},
                [{Daddr, timer:now_diff(erlang:now(), Now), {icmp, Data}}|Acc]);

        % Response from intermediate host
        % ICMP payload
        {icmp, Ref, Addr, {icmp, <<_ICMPHeader:8/bytes, _IPv4Header:20/bytes,
                _Type:8, _Code:8, _Checksum:16, Sport:16, _/binary>> = Data}} ->
            trace(Ref, State#state{ttl = TTL+1},
                [{Addr, timer:now_diff(erlang:now(), Now), {icmp, Data}}|Acc]);

        % UDP payload
        {icmp, Ref, Addr, {udp, << _ICMPHeader:8/bytes, _IPv4Header:20/bytes,
                Sport:16, _/binary>> = Data}} ->
            trace(Ref, State#state{ttl = TTL+1},
                [{Addr, timer:now_diff(erlang:now(), Now), {icmp, Data}}|Acc]);

        % Response from protocol handler
        {tracert, Ref, Saddr, Data} ->
            trace(Ref, State#state{ttl = 0},
                [{Saddr, timer:now_diff(erlang:now(), Now), Data}|Acc])
    after
        Timeout ->
            trace(Ref, State#state{ttl = TTL+1}, [timeout|Acc])
    end.


probe(Ref, Daddr, Dport, TTL, Packet) when is_binary(Packet) ->
    gen_server:call(Ref, {send, Daddr, Dport, TTL, Packet}, infinity).


open() ->
    open([]).
open(Options) ->
    start_link(Options).


close(Ref) ->
    gen_server:call(Ref, close).


path(Path) when is_list(Path) ->
    path(Path, [response(icmp)]).

path(Path, []) ->
    Path;
path(Path, [Fun|Funs]) when is_list(Path), is_function(Fun) ->
    Mapped = lists:map(Fun, Path),
    path(Mapped, Funs).


response(icmp) ->
    fun({Saddr, Microsec, {icmp, Packet}}) ->
            ICMP = icmp_to_atom(Packet),
            {Saddr, Microsec, ICMP};
        (N) ->
            N
    end.


%%-------------------------------------------------------------------------
%%% Callbacks
%%-------------------------------------------------------------------------
start_link(Options) ->
    Pid = self(),
    gen_server:start_link(?MODULE, [Pid, Options], []).

init([Pid, Options]) ->
    process_flag(trap_exit, true),

    State = proplist_to_record(Options),
    #state{
        protocol = Protocol,
        saddr = Saddr,
        sport = Sport,
        setuid = Setuid
    } = State,


    % Read socket: ICMP trace
    {ok, RS} = gen_icmp:open(),

    % Write socket: probes
    {ok, WS} = socket(
        Protocol,
        Saddr,
        Sport,
        Setuid
    ),

    {ok, State#state{
            pid = Pid,
            ws = WS,
            rs = RS
        }}.

handle_call(close, {Pid,_}, #state{pid = Pid} = State) ->
    {stop, normal, ok, State};
handle_call(sport, _From, #state{sport = Sport} = State) ->
    {reply, Sport, State};
handle_call({send, {DA1,DA2,DA3,DA4}, Dport, TTL, Packet}, _From, #state{ws = Socket} = State) ->
    Sockaddr = <<
        (procket:sockaddr_common(?PF_INET, 16))/binary,
        Dport:16,                   % Destination Port
        DA1,DA2,DA3,DA4,            % IPv4 address
        0:64
    >>,
    ok = procket:setsockopt(Socket, ?IPPROTO_IP, ip_ttl(), <<TTL:32/native>>),
    {reply, procket:sendto(Socket, Packet, 0, Sockaddr), State};
handle_call({handler, _Handler}, _From, State) ->
    {reply, ok, State};

handle_call(Request, From, State) ->
    error_logger:info_report([{call, Request}, {from, From}, {state, State}]),
    {reply, ok, State}.

handle_cast(Msg, State) ->
    error_logger:info_report([{cast, Msg}, {state, State}]),
    {noreply, State}.

handle_info({icmp, Socket, Daddr, Data}, #state{pid = Pid, rs = Socket,
        protocol = Protocol} = State) ->
    Pid ! {icmp, self(), Daddr, {Protocol, Data}},
    {noreply, State};
handle_info({tracert, Daddr, Data}, #state{pid = Pid} = State) ->
    Pid ! {tracert, self(), Daddr, Data},
    {noreply, State};

handle_info(Info, State) ->
    error_logger:info_report([{info, Info}, {state, State}]),
    {noreply, State}.

terminate(_Reason, #state{rs = RS, ws = WS}) ->
    procket:close(WS),
    gen_icmp:close(RS),
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.


%%-------------------------------------------------------------------------
%%% Utility Functions
%%-------------------------------------------------------------------------
socket(Protocol, Saddr, Sport) ->
    socket(Protocol, Saddr, Sport, true).

socket(Protocol0, Saddr, Sport, Setuid) ->
    {Protocol, Type, Port} = case Protocol0 of
        icmp -> {icmp, raw, 0};
        udp -> {udp, dgram, Sport};
        _ -> {raw, raw, 0}
    end,
    socket_1(inet, Type, Protocol, Saddr, Port, Setuid).

socket_1(Family, Type, Protocol, Saddr, Sport, true) ->
    procket:open(Sport, [
        {ip, Saddr},
        {family, Family},
        {type, Type},
        {protocol, Protocol}
    ]);
socket_1(Family, Type, Protocol, _Saddr, 0, false) ->
    procket:socket(Family, Type, Protocol);
socket_1(Family, Type, Protocol, {SA1,SA2,SA3,SA4}, Sport, false) ->
    case procket:socket(Family, Type, Protocol) of
        {ok, Socket} ->
            Sockaddr = <<
                (procket:sockaddr_common(?PF_INET, 16))/binary,
                Sport:16,           % Source port
                SA1,SA2,SA3,SA4,    % IPv4 address
                0:64
            >>,
            ok = procket:bind(Socket, Sockaddr),
            {ok, Socket};
        Error ->
            Error
    end.

proplist_to_record(Options) ->
    Default = #state{},

    Protocol = proplists:get_value(protocol, Options, Default#state.protocol),
    Packet = proplists:get_value(packet, Options, protocol(Protocol)),
    Handler = proplists:get_value(handler, Options, Default#state.handler),

    Initial_ttl = proplists:get_value(ttl, Options, Default#state.ttl),
    Max_hops = proplists:get_value(max_hops, Options, Default#state.max_hops),
    Timeout = proplists:get_value(timeout, Options, Default#state.timeout),
    Setuid = proplists:get_value(setuid, Options, Default#state.setuid),

    Saddr = proplists:get_value(saddr, Options, Default#state.saddr),
    Sport = proplists:get_value(sport, Options, crypto:rand_uniform(16#8000, 16#FFFF)),
    Dport = proplists:get_value(dport, Options, dport(Protocol)),

    Next_port = proplists:get_value(next_port, Options, next_port(Protocol)),

    true = Initial_ttl < Max_hops,
    true = Initial_ttl > 0,

    #state{
        protocol = Protocol,
        packet = Packet,
        handler = Handler,
        ttl = Initial_ttl,
        max_hops = Max_hops,
        timeout = Timeout,
        setuid = Setuid,
        saddr = Saddr,
        sport = Sport,

        dport = Dport,
        next_port = Next_port
    }.


%%-------------------------------------------------------------------------
%%% Internal Functions
%%-------------------------------------------------------------------------
icmp_to_atom(ICMP) when is_binary(ICMP) ->
    {#icmp{type = Type,
        code = Code}, _Payload} = pkt:icmp(ICMP),
    gen_icmp:code({Type,  Code}).


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
    fun({_Saddr, Sport}, {_Daddr, _Dport}, _TTL) ->
        gen_icmp:echo(Sport, 0, <<(list_to_binary(lists:seq($\s, $W)))/binary>>)
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


flush_events(Ref) ->
    receive
        {Event, Ref, _Addr, _Data} when Event == icmp; Event == tracert ->
            flush_events(Ref)
    after
            0 -> ok
    end.
