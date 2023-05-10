%%% @copyright 2011-2023 Michael Santos <michael.santos@gmail.com>
%%% All rights reserved.
%%%
%%% Redistribution and use in source and binary forms, with or without
%%% modification, are permitted provided that the following conditions
%%% are met:
%%%
%%% 1. Redistributions of source code must retain the above copyright notice,
%%% this list of conditions and the following disclaimer.
%%%
%%% 2. Redistributions in binary form must reproduce the above copyright
%%% notice, this list of conditions and the following disclaimer in the
%%% documentation and/or other materials provided with the distribution.
%%%
%%% 3. Neither the name of the copyright holder nor the names of its
%%% contributors may be used to endorse or promote products derived from
%%% this software without specific prior written permission.
%%%
%%% THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
%%% "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
%%% LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
%%% A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
%%% HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
%%% SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
%%% TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
%%% PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
%%% LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
%%% NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
%%% SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

%% @doc Perform a traceroute
%%
%% Send a probe packet with the time to live set from 1. Monitor
%% an ICMP socket for ICMP responses or timeout.
%%
%% == Examples ==
%%
%% ```
%% 1> tracert:host("hex.pm").
%% '''
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
    socket/4,
    proplist_to_record/1,
    probe/5,
    response/1
]).

-export([start_link/1]).
%% gen_server callbacks
-export([
    init/1,
    handle_call/3,
    handle_cast/2,
    handle_info/2,
    terminate/2,
    code_change/3
]).

-record(state, {
    pid,

    family = inet,
    protocol = icmp,
    ttl = 1,
    max_hops = 31,
    % 1 second
    timeout = 1000,

    packet,
    handler,
    dport = 0,
    sport = 0,
    next_port,

    saddr = {0, 0, 0, 0},
    daddr,
    ws,
    rs
}).

-type socket() :: pid().
-type option() ::
    {family, inet | inet6}
    | {protocol, icmp | udp}
    | {ttl, non_neg_integer()}
    | {max_hops, non_neg_integer()}
    | {timeout, non_neg_integer() | infinity}
    | {packet, binary()}
    | {dport, gen_icmp:uint16_t()}
    | {sport, gen_icmp:uint16_t()}
    | {next_port, gen_icmp:uint16_t()}
    | {saddr, inet:socket_address()}
    | {daddr, inet:socket_address()}.

-export_type([
    option/0,
    socket/0
]).

-ifndef(PF_INET6).
-define(PF_INET6, family(inet6)).
-endif.

%% @doc Perform an ICMP traceroute to a destination.
%%
%% == Examples ==
%%
%% ```
%% 1> tracert:host("google.com").
%% [timeout,
%%  {{142,250,57,128},
%%   1174,
%%   {icmp,<<11,0,111,150,0,0,0,0,69,96,0,84,128,116,64,0,1,
%%           1,125,44,10,128,...>>}},
%%  {{172,253,79,98},
%%   3418,
%%   {icmp,<<11,0,244,238,0,17,0,0,69,96,0,84,128,117,64,0,1,
%%           1,125,43,10,...>>}},
%%  {{192,178,45,217},
%%   4103,
%%   {icmp,<<11,0,111,113,0,17,0,0,69,96,0,84,128,118,64,0,1,
%%           1,125,42,...>>}},
%%  {{216,239,57,177},
%%   2233,
%%   {icmp,<<11,0,111,113,0,17,0,0,69,96,0,84,128,119,64,0,1,
%%           1,125,...>>}},
%%  timeout,timeout,timeout,timeout,timeout,timeout,timeout,
%%  timeout,timeout,
%%  {{173,194,195,100},
%%   975,
%%   {icmp,<<0,0,184,52,205,52,0,0,32,...>>}}]
%% '''
-spec host(inet:socket_address() | inet:hostname()) ->
    [{inet:socket_address(), MicroSeconds :: integer(), {icmp | udp, binary()}} | timeout].
host(Host) ->
    host(Host, []).

%% @doc Perform a traceroute to a destination with options.
%%
%% == Examples ==
%%
%% ```
%% 1> tracert:host("google.com", [{protocol, udp}]).
%% [timeout,
%%  {{142,250,57,212},
%%   3671,
%%   {icmp,<<11,0,0,16,0,0,0,0,69,96,0,28,1,92,64,0,1,17,109,
%%           31,10,128,...>>}},
%%  {{142,250,231,47},
%%   2081,
%%   {icmp,<<11,0,255,254,0,17,0,0,69,96,0,28,1,93,64,0,1,17,
%%           109,30,10,...>>}},
%%  {{142,251,236,131},
%%   1322,
%%   {icmp,<<11,0,255,254,0,17,0,0,69,96,0,28,1,94,64,0,1,17,
%%           109,29,...>>}},
%%  {{108,170,234,239},
%%   3121,
%%   {icmp,<<11,0,255,254,0,17,0,0,69,96,0,28,1,95,64,0,1,17,
%%           109,...>>}},
%%  timeout,timeout,timeout,timeout,timeout,timeout,timeout,
%%  timeout,timeout,
%%  {{64,233,191,139},917,{icmp,<<3,3,8,13,0,0,0,0,69,...>>}}]
%% '''
-spec host(inet:socket_address() | inet:hostname(), [option()]) ->
    [{inet:socket_address(), MicroSeconds :: integer(), {icmp | udp, binary()}} | timeout].
host(Host, Options) ->
    {ok, Socket} = open(Options),
    Path = host(Socket, Host, Options),
    close(Socket),
    Path.

%% @doc Perform a traceroute to a destination
%%
%% ICMP and UDP probes are supported. ICMP probes are the default.
%%
%% max_hops is the maximum TTL (default: 30)
%%
%% Set the time in milliseconds to wait for a response using the
%% timeout option (default: 1000 ms).  WARNING: if the response
%% arrives after the timeout, tracert will insert spurious entries
%% into the path.
%%
%% tracert will not spawn the setuid helper if the `{setuid, false}'
%% option is used. In this case, beam must either be running as
%% root or have the cap_net_raw privileges under Linux.
%%
%% The {sport, Port} option sets the initial source port for UDP
%% probes. The port will be incremented by 1 for each subsequent
%% probe (default: random high port).  For ICMP probes, the ICMP
%% ID field will be set to this value.
%%
%% The return value is an ordered list of tuples:
%%
%% * Address: the source address responding to the probe
%%
%% * MicroSeconds: time elapsed between the probe and receiving
%%   the response
%%
%% * Protocol: icmp or udp
%%
%% * Protocol data: a binary representing the received packet
%%   contents
%%
%% == Examples ==
%%
%% ```
%% 1> {ok, Socket} = tracert:open().
%% {ok,<0.164.0>}
%% 2> Path = tracert:host(Socket, "8.8.8.8", []).
%% [timeout,timeout,timeout,timeout,timeout,timeout,timeout,
%%  timeout,timeout,timeout,
%%  {{8,8,8,8},
%%   750,
%%   {icmp,<<0,0,231,24,158,80,0,0,32,33,34,35,36,...>>}}]
%% 3> tracert:close(Socket).
%% ok
%% 4> tracert:path(Path).
%% [timeout,timeout,timeout,timeout,timeout,timeout,timeout,
%%  timeout,timeout,timeout,
%%  {{8,8,8,8},750,echoreply}]
%% '''
-spec host(socket(), inet:socket_address() | inet:hostname(), [option()]) ->
    [{inet:socket_address(), MicroSeconds :: integer(), {icmp | udp, binary()}} | timeout].
host(Socket, Host, Options) ->
    State = proplist_to_record(Options),
    #state{family = Family} = State,
    {ok, [Daddr | _]} = gen_icmp:parse(Family, Host),
    ok = gen_server:call(Socket, {handler, State#state.handler}, infinity),
    trace(Socket, State#state{daddr = Daddr}).

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
trace(
    Ref,
    #state{
        daddr = Daddr,
        dport = Dport,

        saddr = Saddr,
        sport = Sport,

        ttl = TTL,
        packet = Fun,
        next_port = Next,

        timeout = Timeout
    } = State0,
    Acc
) ->
    State = State0#state{dport = Next(Dport)},
    Packet = Fun({Saddr, Sport}, {Daddr, Dport}, TTL),
    ok = probe(Ref, Daddr, Dport, TTL, Packet),

    Now = gen_icmp:gettime(),

    % No catch all match because packets may be received after the timeout
    receive
        % Response from destination
        {icmp, Ref, Daddr, {_, Data}} ->
            trace(
                Ref,
                State#state{ttl = 0},
                [{Daddr, gen_icmp:timediff(Now), {icmp, Data}} | Acc]
            );
        % Response from intermediate host
        % IPv4 ICMP payload
        {icmp, Ref, {_, _, _, _} = Addr,
            {icmp,
                <<_ICMPHeader:8/bytes, _IPv4Header:20/bytes, _Type:8, _Code:8, _Checksum:16,
                    Sport:16, _/binary>> = Data}} ->
            trace(
                Ref,
                State#state{ttl = TTL + 1},
                [{Addr, gen_icmp:timediff(Now), {icmp, Data}} | Acc]
            );
        % IPv6 ICMP payload
        {icmp, Ref, {_, _, _, _, _, _, _, _} = Addr,
            {icmp,
                <<_ICMPHeader:8/bytes, _IPv6Header:40/bytes, _Type:8, _Code:8, _Checksum:16,
                    Sport:16, _/binary>> = Data}} ->
            trace(
                Ref,
                State#state{ttl = TTL + 1},
                [{Addr, gen_icmp:timediff(Now), {icmp, Data}} | Acc]
            );
        % IPv4 UDP payload
        {icmp, Ref, {_, _, _, _} = Addr,
            {udp, <<_ICMPHeader:8/bytes, _IPv4Header:20/bytes, Sport:16, _/binary>> = Data}} ->
            trace(
                Ref,
                State#state{ttl = TTL + 1},
                [{Addr, gen_icmp:timediff(Now), {icmp, Data}} | Acc]
            );
        % IPv6 UDP payload
        {icmp, Ref, {_, _, _, _, _, _, _, _} = Addr,
            {udp, <<_ICMPHeader:8/bytes, _IPv6Header:40/bytes, _Sport:16, _/binary>> = Data}} ->
            trace(
                Ref,
                State#state{ttl = TTL + 1},
                [{Addr, gen_icmp:timediff(Now), {icmp, Data}} | Acc]
            );
        % Response from protocol handler
        {tracert, Ref, Saddr, Data} ->
            trace(
                Ref,
                State#state{ttl = 0},
                [{Saddr, gen_icmp:timediff(Now), Data} | Acc]
            )
    after Timeout ->
        trace(Ref, State#state{ttl = TTL + 1}, [timeout | Acc])
    end.

probe(Ref, Daddr, Dport, TTL, Packet) when is_binary(Packet) ->
    gen_server:call(Ref, {send, Daddr, Dport, TTL, Packet}, infinity).

%% @doc Open an ICMP socket for traceroute
%%
%% == Examples ==
%%
%% ```
%% 1> {ok, Socket} = tracert:open().
%% {ok,<0.164.0>}
%% '''
-spec open() -> {ok, socket()} | {error, system_limit | inet:posix()}.
open() ->
    open([]).

%% @doc Open an ICMP socket for traceroute
%%
%% == Examples ==
%%
%% ```
%% 1> {ok, Socket} = tracert:open([inet6, {protocol, udp}]).
%% {ok,<0.289.0>}
%% '''
-spec open([option()]) -> {ok, socket()} | {error, system_limit | inet:posix()}.
open(Options) ->
    start_link(Options).

%% @doc Close the ICMP socket
%%
%% == Examples ==
%%
%% ```
%% 1> {ok, Socket} = tracert:open().
%% {ok,<0.164.0>}
%% 2> tracert:close(Socket).
%% ok
%% '''
-spec close(socket()) -> ok.
close(Socket) ->
    gen_server:call(Socket, close).

%% @doc Convert trace response to atoms.
%%
%% Convert the list of binaries returned by host/1,2,3 to atoms
%% representing the ICMP response codes and UDP errors.
%%
%% == Examples ==
%%
%% ```
%% 1> {ok, Socket} = tracert:open().
%% {ok,<0.164.0>}
%% 2> Path = tracert:host(Socket, "8.8.8.8", []).
%% [timeout,timeout,timeout,timeout,timeout,timeout,timeout,
%%  timeout,timeout,timeout,
%%  {{8,8,8,8},
%%   750,
%%   {icmp,<<0,0,231,24,158,80,0,0,32,33,34,35,36,...>>}}]
%% 3> tracert:close(Socket).
%% ok
%% 4> tracert:path(Path).
%% [timeout,timeout,timeout,timeout,timeout,timeout,timeout,
%%  timeout,timeout,timeout,
%%  {{8,8,8,8},750,echoreply}]
%% '''
path(Path) when is_list(Path) ->
    path(Path, [response(icmp)]).

path(Path, []) ->
    Path;
path(Path, [Fun | Funs]) when is_list(Path), is_function(Fun) ->
    Mapped = lists:map(Fun, Path),
    path(Mapped, Funs).

response(icmp) ->
    fun
        ({{_, _, _, _} = Saddr, Microsec, {icmp, Packet}}) ->
            ICMP = icmp_to_atom(inet, Packet),
            {Saddr, Microsec, ICMP};
        ({{_, _, _, _, _, _, _, _} = Saddr, Microsec, {icmp, Packet}}) ->
            ICMP = icmp_to_atom(inet6, Packet),
            {Saddr, Microsec, ICMP};
        (N) ->
            N
    end.

%%-------------------------------------------------------------------------
%%% Callbacks
%%-------------------------------------------------------------------------
% @private
start_link(Options) ->
    Pid = self(),
    gen_server:start_link(?MODULE, [Pid, Options], []).

% @private
init([Pid, Options]) ->
    process_flag(trap_exit, true),

    State = proplist_to_record(Options),
    #state{
        family = Family,
        protocol = Protocol,
        saddr = Saddr,
        sport = Sport
    } = State,

    % Read socket: ICMP trace
    {ok, RS} = gen_icmp:open([Family], [{active, true}]),

    % Write socket: probes
    {ok, WS} = socket(
        Family,
        Protocol,
        Saddr,
        Sport
    ),

    {ok, State#state{
        pid = Pid,
        ws = WS,
        rs = RS
    }}.

% @private
handle_call(close, {Pid, _}, #state{pid = Pid} = State) ->
    {stop, normal, ok, State};
handle_call(sport, _From, #state{sport = Sport} = State) ->
    {reply, Sport, State};
handle_call(
    {send, {DA1, DA2, DA3, DA4}, Dport, TTL, Packet},
    _From,
    #state{ws = Socket} = State
) ->
    Sockaddr = <<
        (procket:sockaddr_common(?PF_INET, 16))/binary,
        % Destination Port
        Dport:16,
        % IPv4 address
        DA1,
        DA2,
        DA3,
        DA4,
        0:64
    >>,
    ok = gen_icmp:set_ttl(Socket, inet, TTL),
    {reply, procket:sendto(Socket, Packet, 0, Sockaddr), State};
handle_call(
    {send, {DA1, DA2, DA3, DA4, DA5, DA6, DA7, DA8}, Dport, TTL, Packet},
    _From,
    #state{ws = Socket} = State
) ->
    Sockaddr = <<
        (procket:sockaddr_common(?PF_INET6, 16))/binary,
        % Destination Port
        Dport:16,
        % Flow info
        0:32,
        % IPv6 address
        DA1:16,
        DA2:16,
        DA3:16,
        DA4:16,
        DA5:16,
        DA6:16,
        DA7:16,
        DA8:16,
        % Scope ID
        0:32
    >>,
    ok = gen_icmp:set_ttl(Socket, inet6, TTL),
    {reply, procket:sendto(Socket, Packet, 0, Sockaddr), State};
handle_call({handler, _Handler}, _From, State) ->
    {reply, ok, State};
handle_call(Request, From, State) ->
    error_logger:info_report([{call, Request}, {from, From}, {state, State}]),
    {reply, ok, State}.

% @private
handle_cast(Msg, State) ->
    error_logger:info_report([{cast, Msg}, {state, State}]),
    {noreply, State}.

% @private
handle_info(
    {icmp, Socket, Daddr, _TTL, Data},
    #state{
        pid = Pid,
        rs = Socket,
        protocol = Protocol
    } = State
) ->
    Pid ! {icmp, self(), Daddr, {Protocol, Data}},
    {noreply, State};
handle_info({tracert, Daddr, Data}, #state{pid = Pid} = State) ->
    Pid ! {tracert, self(), Daddr, Data},
    {noreply, State};
handle_info({'EXIT', _, normal}, State) ->
    {noreply, State};
handle_info(Info, State) ->
    error_logger:info_report([{info, Info}, {state, State}]),
    {noreply, State}.

% @private
terminate(_Reason, #state{rs = RS, ws = WS}) ->
    procket:close(WS),
    gen_icmp:close(RS),
    ok.

% @private
code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%%-------------------------------------------------------------------------
%%% Utility Functions
%%-------------------------------------------------------------------------
socket(Family, Protocol0, Saddr, Sport) ->
    {Protocol, Type, Port} =
        case {Family, Protocol0} of
            {inet, icmp} -> {icmp, raw, 0};
            {inet6, icmp} -> {'ipv6-icmp', raw, 0};
            {_, udp} -> {udp, dgram, Sport}
        end,

    open_socket(Family, Type, Protocol, Saddr, Port).

open_socket(Family, Type, Protocol, Saddr, Sport) ->
    case procket:socket(Family, Type, Protocol) of
        {error, eperm} ->
            procket:open(Sport, [
                {ip, Saddr},
                {family, Family},
                {type, Type},
                {protocol, Protocol}
            ]);
        {ok, Socket} ->
            bind_socket(Socket, Family, Saddr, Sport);
        Error ->
            Error
    end.

bind_socket(Socket, inet, {SA1, SA2, SA3, SA4}, Sport) ->
    Sockaddr = <<
        (procket:sockaddr_common(?PF_INET, 16))/binary,
        % Source port
        Sport:16,
        % IPv4 address
        SA1,
        SA2,
        SA3,
        SA4,
        0:64
    >>,

    case procket:bind(Socket, Sockaddr) of
        ok -> {ok, Socket};
        Error -> Error
    end;
bind_socket(Socket, inet6, {SA1, SA2, SA3, SA4, SA5, SA6, SA7, SA8}, Sport) ->
    Sockaddr = <<
        (procket:sockaddr_common(?PF_INET6, 16))/binary,
        % Source port
        Sport:16,
        % IPv6 flow information
        0:32,
        % IPv6 address
        SA1:16,
        SA2:16,
        SA3:16,
        SA4:16,
        SA5:16,
        SA6:16,
        SA7:16,
        SA8:16,
        % IPv6 scope id
        0:32
    >>,

    case procket:bind(Socket, Sockaddr) of
        ok -> {ok, Socket};
        Error -> Error
    end.

proplist_to_record(Options) ->
    Default = #state{},

    {Family, Saddr} =
        case proplists:get_value(inet6, Options, false) of
            true -> {inet6, {0, 0, 0, 0, 0, 0, 0, 0}};
            false -> {Default#state.family, Default#state.saddr}
        end,
    Protocol = proplists:get_value(protocol, Options, Default#state.protocol),
    Packet = proplists:get_value(packet, Options, protocol(Protocol)),
    Handler = proplists:get_value(handler, Options, Default#state.handler),

    Initial_ttl = proplists:get_value(ttl, Options, Default#state.ttl),
    Max_hops = proplists:get_value(max_hops, Options, Default#state.max_hops),
    Timeout = proplists:get_value(timeout, Options, Default#state.timeout),

    Saddr = proplists:get_value(saddr, Options, Saddr),
    Sport = proplists:get_value(sport, Options, 16#7FFF + rand:uniform(16#8000)),
    Dport = proplists:get_value(dport, Options, dport(Protocol)),

    Next_port = proplists:get_value(next_port, Options, next_port(Protocol)),

    true = Initial_ttl < Max_hops,
    true = Initial_ttl > 0,

    #state{
        family = Family,
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

%%-------------------------------------------------------------------------
%%% Internal Functions
%%-------------------------------------------------------------------------
icmp_to_atom(inet, ICMP) when is_binary(ICMP) ->
    {
        #icmp{
            type = Type,
            code = Code
        },
        _Payload
    } = pkt:icmp(ICMP),
    icmp_message:code({Type, Code});
icmp_to_atom(inet6, ICMP) when is_binary(ICMP) ->
    {
        #icmp6{
            type = Type,
            code = Code
        },
        _Payload
    } = pkt:icmp6(ICMP),
    icmp6_message:code({Type, Code}).

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
    fun
        ({{_, _, _, _}, Sport}, {_Daddr, _Dport}, _TTL) ->
            gen_icmp:echo(inet, Sport, 0, <<(list_to_binary(lists:seq($\s, $W)))/binary>>);
        ({{_, _, _, _, _, _, _, _}, Sport}, {_Daddr, _Dport}, _TTL) ->
            gen_icmp:echo(inet6, Sport, 0, <<(list_to_binary(lists:seq($\s, $W)))/binary>>)
    end.

%%
%% Calculate the port for different protocol types
%%
dport(udp) -> 1 bsl 15 + 666;
dport(icmp) -> 0.

next_port(udp) ->
    fun(N) -> N + 1 end;
next_port(_) ->
    fun(N) -> N end.

flush_events(Ref) ->
    receive
        {Event, Ref, _Addr, _Data} when Event == icmp; Event == tracert ->
            flush_events(Ref)
    after 0 -> ok
    end.

family(inet6) ->
    case os:type() of
        {unix, darwin} -> 30;
        {unix, freebsd} -> 28;
        {unix, linux} -> 10;
        {unix, netbsd} -> 24;
        {unix, openbsd} -> 24
    end.
