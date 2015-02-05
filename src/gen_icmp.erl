%% Copyright (c) 2010-2013, Michael Santos <michael.santos@gmail.com>
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
-module(gen_icmp).
-behaviour(gen_server).
-include_lib("kernel/include/inet.hrl").
-include_lib("pkt/include/pkt.hrl").

-define(SERVER, ?MODULE).

-define(PING_TIMEOUT, 5000).

-export([
    open/0, open/1, open/2,
    close/1,
    send/3,
    controlling_process/2,
    setopts/2,
    family/1,
    getfd/1,
    set_ttl/3,
    get_ttl/2,

    filter/1, filter/2,
    icmp6_filter_setpassall/0,
    icmp6_filter_setblockall/0,
    icmp6_filter_setpass/2,
    icmp6_filter_setblock/2,
    icmp6_filter_willpass/2,
    icmp6_filter_willblock/2
    ]).
-export([recv/2, recv/3]).
-export([ping/1, ping/2, ping/3]).
-export([
        echo/3, echo/4,
        packet/2, packet/3,
        parse/1, parse/2
    ]).

-export([start_link/2, start/2]).
%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
	 terminate/2, code_change/3]).

-record(state, {
        family = inet,  % Protocol family (inet, inet6)
        pid,            % caller PID
        fd,             % socket file descriptor
        s               % udp socket
}).

-record(ping_opt, {
        s,
        id,
        sequence,
        timeout,
        tref,
        timestamp = true
    }).

-record(icmp6_pseudohdr, {
        saddr = {0,0,0,0,0,0,0,0},
        daddr = {0,0,0,0,0,0,0,0},
        len = 0,
        next = ?IPPROTO_ICMPV6,
        h = #icmp6{}
        }).

%%-------------------------------------------------------------------------
%%% API
%%-------------------------------------------------------------------------
open() ->
    open([], []).
open(RawOpts) ->
    open(RawOpts, []).
open(RawOpts, SockOpts) ->
    start_link(RawOpts, SockOpts).

close(Ref) when is_pid(Ref) ->
    gen_server:call(Ref, close, infinity).

send(Ref, Address, Packet) when is_pid(Ref) ->
    gen_server:call(Ref, {send, Address, Packet}, infinity).

recv(Ref, Length) ->
    recv(Ref, Length, infinity).
recv(Ref, Length, Timeout) ->
    gen_server:call(Ref, {recv, Length, Timeout}, infinity).

controlling_process(Ref, Pid) when is_pid(Ref), is_pid(Pid) ->
    gen_server:call(Ref, {controlling_process, Pid}, infinity).

setopts(Ref, Options) when is_pid(Ref), is_list(Options) ->
    gen_server:call(Ref, {setopts, Options}, infinity).

family(Ref) when is_pid(Ref) ->
    gen_server:call(Ref, family, infinity).

getfd(Ref) when is_pid(Ref) ->
    gen_server:call(Ref, getfd, infinity).

filter(Ref) when is_pid(Ref) ->
    gen_server:call(Ref, filter, infinity).
filter(Ref, Filter) when is_pid(Ref) ->
    gen_server:call(Ref, {filter, Filter}, infinity).

ping(Host) ->
    ping(Host, []).

ping(Host, Options) when is_tuple(Host) ->
    ping([Host], Options);
ping([Char|_] = Host, Options) when is_integer(Char) ->
    ping([Host], Options);
ping(Hosts, Options) ->
    {ok, Socket} = gen_icmp:open(Options),
    Res = ping(Socket, Hosts, Options),
    gen_icmp:close(Socket),
    Res.

ping(Socket, Hosts, Options) when is_pid(Socket), is_list(Hosts), is_list(Options) ->
    ok = setopts(Socket, [{active,true}]),

    Family = family(Socket),

    Id = proplists:get_value(id, Options, erlang:phash2(self(), 16#FFFF)),
    Seq = proplists:get_value(sequence, Options, 0),
    Data = proplists:get_value(data, Options, payload(echo)),
    Timeout = proplists:get_value(timeout, Options, ?PING_TIMEOUT),
    Timestamp = proplists:get_value(timestamp, Options, true),
    Dedup = proplists:get_value(dedup, Options, true),
    Multi = proplists:get_value(multi, Options, false),

    ICMP6_filter = lists:foldl(fun(T,X) ->
            gen_icmp:icmp6_filter_setpass(T, X)
        end,
        gen_icmp:icmp6_filter_setblockall(),
        [echo_reply, dst_unreach, packet_too_big,
         time_exceeded, param_prob]),

    Filter = proplists:get_value(filter, Options, ICMP6_filter),

    ok = case Family of
        inet6 ->
            filter(Socket, Filter);
        _ ->
            ok
    end,

    Hosts2 = addr_list(Family, Hosts, Dedup, Multi),

    {Addresses, Errors, _} = lists:foldl(
            fun({ok, Host, Addr}, {NHosts, Nerr, NSeq}) ->
                    {[{ok, Host, Addr, NSeq}|NHosts], Nerr, NSeq+1};
               (Err, {NHosts, Nerr, NSeq}) ->
                    {NHosts, [Err|Nerr], NSeq}
            end,
            {[], [], Seq},
            Hosts2),

    Result = case Addresses of
        [] ->
            Errors;
        _ ->
            [ spawn(fun() ->
                            gen_icmp:send(Socket, Addr, gen_icmp:echo(Family, Id, S, Data))
                    end) || {ok, _Host, Addr, S} <- Addresses ],
            {Timeouts, Replies} = ping_reply(Addresses, #ping_opt{
                                             s = Socket,
                                             id = Id,
                                             timeout = Timeout,
                                             timestamp = Timestamp
                                            }),
            Errors ++ Timeouts ++ Replies
    end,

    ok = setopts(Socket, [{active,false}]),
    flush_events(Socket),
    Result.


%%-------------------------------------------------------------------------
%%% Callbacks
%%-------------------------------------------------------------------------
start_link(RawOpts, SockOpts) ->
    Pid = self(),
    gen_server:start_link(?MODULE, [Pid, RawOpts, SockOpts], []).

start(RawOpts, SockOpts) ->
    Pid = self(),
    case gen_server:start(?MODULE, [Pid, RawOpts, SockOpts], []) of
        {ok, Socket} -> {ok, Socket};
        {error, Error} -> Error
    end.

init([Pid, RawOpts, SockOpts]) ->
    process_flag(trap_exit, true),

    {Protocol, Family} = case proplists:get_value(inet6, RawOpts, false) of
        false -> {icmp, inet};
        true -> {'ipv6-icmp', inet6}
    end,

    Result = case procket:socket(Family, raw, Protocol) of
        {error, eperm} ->
            procket:open(0, RawOpts ++ [{protocol, Protocol}, {type, raw}, {family, Family}]);
        N ->
            N
    end,

    init_1(Pid, Family, RawOpts, SockOpts, Result).

init_1(Pid, Family, RawOpts, SockOpts0, {ok, FD}) ->
    TTL = proplists:get_value(ttl, RawOpts),

    case TTL of
        undefined -> ok;
        _ -> set_ttl(FD, Family, TTL)
    end,

    SockOpts = case proplists:is_defined(active, SockOpts0) of
        true -> SockOpts0;
        false -> SockOpts0 ++ [{active, false}]
    end,

    case gen_udp:open(0, SockOpts ++ [binary, {fd, FD}, Family]) of
        {ok, Socket} ->
            {ok, #state{
                family = Family,
                pid = Pid,
                fd = FD,
                s = Socket
            }};
        Error ->
            Error
    end;
init_1(_Pid, _Family, _RawOpts, _SockOpts, Error) ->
    {stop, Error}.

handle_call(close, {Pid,_}, #state{pid = Pid, s = Socket} = State) ->
    {stop, normal, gen_udp:close(Socket), State};
handle_call({send, IP, Packet}, _From, #state{s = Socket} = State) ->
    {reply, gen_udp:send(Socket, IP, 0, Packet), State};
handle_call({recv, Length, Timeout}, {Pid,_}, #state{pid = Pid, s = Socket} = State) ->
    Reply = case gen_udp:recv(Socket, Length, Timeout) of
        {ok, {Address, _Port, Packet}} -> {ok, {Address, Packet}};
        N -> N
    end,
    {reply, Reply, State};
handle_call({controlling_process, Pid}, {Owner,_}, #state{pid = Owner} = State) ->
    {reply, ok, State#state{pid = Pid}};
handle_call({setopts, Options}, {Pid,_}, #state{pid = Pid, s = Socket} = State) ->
    {reply, inet:setopts(Socket, Options), State};
handle_call(family, _From, #state{family = Family} = State) ->
    {reply, Family, State};
handle_call(getfd, _From, #state{fd = Socket} = State) ->
    {reply, Socket, State};

handle_call(filter, _From, #state{family = inet6, fd = Socket} = State) ->
    Reply = procket:getsockopt(Socket, ?IPPROTO_ICMPV6, icmp6_filter(), <<0:256>>),
    {reply, Reply, State};
handle_call(filter, _From, State) ->
    {reply, unsupported, State};
handle_call({filter, Filter}, _From, #state{family = inet6, fd = Socket} = State) ->
    Reply = procket:setsockopt(Socket, ?IPPROTO_ICMPV6, icmp6_filter(), Filter),
    {reply, Reply, State};
handle_call({filter, _Filter}, _From, State) ->
    {reply, unsupported, State};

handle_call(Request, From, State) ->
    error_logger:info_report([{call, Request}, {from, From}, {state, State}]),
    {reply, error, State}.

handle_cast(Msg, State) ->
    error_logger:info_report([{cast, Msg}, {state, State}]),
    {noreply, State}.


% IPv4 ICMP
handle_info({udp, Socket, {_,_,_,_} = Saddr, 0,
        <<4:4, HL:4, _ToS:8, _Len:16, _Id:16, 0:1, _DF:1, _MF:1,
          _Off:13, TTL:8, ?IPPROTO_ICMP:8, _Sum:16,
          _SA1:8, _SA2:8, _SA3:8, _SA4:8,
          _DA1:8, _DA2:8, _DA3:8, _DA4:8,
          Data/binary>>}, #state{pid = Pid, s = Socket} = State) ->

    N = (HL-5)*4,
    Opt = if
        N > 0 -> N;
        true -> 0
    end,

    <<_:Opt/bits, Payload/bits>> = Data,
    Pid ! {icmp, self(), Saddr, TTL, Payload},
    {noreply, State};

% IPv6 ICMP
handle_info({udp, Socket, {_,_,_,_,_,_,_,_} = Saddr, 0, Data},
            #state{pid = Pid, fd = FD, s = Socket} = State) ->
    {ok, TTL} = get_ttl(FD, inet6),
    Pid ! {icmp, self(), Saddr, TTL, Data},
    {noreply, State};

handle_info({'EXIT',_,normal}, State) ->
    {noreply, State};

handle_info(Info, State) ->
    error_logger:info_report([{info, Info}, {state, State}]),
    {noreply, State}.

terminate(_Reason, #state{fd = Socket}) ->
    procket:close(Socket),
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.


%%-------------------------------------------------------------------------
%%% Utility Functions
%%-------------------------------------------------------------------------

%% Create an ICMP packet
packet(#icmp{} = Header, Payload) when is_binary(Payload) ->
    Sum = pkt:makesum(list_to_binary([
                pkt:icmp(Header),
                Payload
            ])),
    list_to_binary([
        pkt:icmp(Header#icmp{checksum = Sum}),
        Payload
    ]);
packet(#icmp6_pseudohdr{
                saddr = {SA1,SA2,SA3,SA4,SA5,SA6,SA7,SA8},
                daddr = {DA1,DA2,DA3,DA4,DA5,DA6,DA7,DA8},
                len = Len,
                next = Next,
                h = Header
                }, Payload) when is_binary(Payload) ->

    Sum = pkt:makesum(list_to_binary([
                    <<SA1,SA2,SA3,SA4,SA5,SA6,SA7,SA8,
                      DA1,DA2,DA3,DA4,DA5,DA6,DA7,DA8,
                      Len:32,
                      0:24,
                      Next:8>>,
                pkt:icmp6(Header),
                Payload
            ])),
    list_to_binary([
        pkt:icmp6(Header#icmp6{checksum = Sum}),
        Payload
    ]);
packet(Header, Payload) ->
    packet(inet, Header, Payload).

% IPv4 ICMP packet
packet(inet, Header, Payload) when is_list(Header), is_binary(Payload) ->
    Default = #icmp{},

    Type = icmp_message:type_to_uint8(
            proplists:get_value(type, Header, Default#icmp.type)
            ),
    Code = icmp_message:code_to_uint8(
            proplists:get_value(code, Header, Default#icmp.code)
            ),

    Id = proplists:get_value(id, Header, Default#icmp.id),
    Seq = proplists:get_value(sequence, Header, Default#icmp.sequence),
    GW = proplists:get_value(gateway, Header, Default#icmp.gateway),
    UN = proplists:get_value(un, Header, Default#icmp.un),
    MTU = proplists:get_value(mtu, Header, Default#icmp.mtu),
    Pointer = proplists:get_value(pointer, Header, Default#icmp.pointer),
    TS_orig = proplists:get_value(ts_orig, Header, Default#icmp.ts_orig),
    TS_recv = proplists:get_value(ts_recv, Header, Default#icmp.ts_recv),
    TS_tx = proplists:get_value(ts_tx, Header, Default#icmp.ts_tx),

    ICMP = #icmp{
            type = Type,
            code = Code,
            id = Id,
            sequence = Seq,
            gateway = GW,
            un = UN,
            mtu = MTU,
            pointer = Pointer,
            ts_orig = TS_orig,
            ts_recv = TS_recv,
            ts_tx = TS_tx
        },
    packet(ICMP, Payload);

% IPv6 ICMP packet
packet(inet6, Header, Payload) when is_list(Header), is_binary(Payload) ->
    Default = #icmp6{},

    Type = icmp6_message:type_to_uint8(
            proplists:get_value(type, Header, Default#icmp6.type)
            ),
    Code = icmp6_message:code_to_uint8(
            proplists:get_value(code, Header, Default#icmp6.code)
            ),

    Id = proplists:get_value(id, Header, Default#icmp6.id),
    Seq = proplists:get_value(sequence, Header, Default#icmp6.seq),
    UN = proplists:get_value(un, Header, Default#icmp6.un),
    MTU = proplists:get_value(mtu, Header, Default#icmp6.mtu),
    Pointer = proplists:get_value(pointer, Header, Default#icmp6.pptr),
    Maxdelay = proplists:get_value(maxdelay, Header, Default#icmp6.maxdelay),

    % IPv6 pseudoheader
    Saddr = proplists:get_value(saddr, Header, {0,0,0,0,0,0,0,0}),
    Daddr = proplists:get_value(daddr, Header, {0,0,0,0,0,0,0,0}),
    Len = proplists:get_value(len, Header, 0),
    Next = proplists:get_value(next, Header, ?IPPROTO_ICMPV6),

    Pseudo = #icmp6_pseudohdr{
            saddr = Saddr,
            daddr = Daddr,
            len = Len,
            next = Next,
            h = #icmp6{
                type = Type,
                code = Code,
                id = Id,
                seq = Seq,
                un = UN,
                mtu = MTU,
                pptr = Pointer,
                maxdelay = Maxdelay
            }
        },

    packet(Pseudo, Payload).


echo(Family, Id, Seq) ->
    % Pad packet to 64 bytes
    echo(Family, Id, Seq, payload(echo)).
echo(Family, Id, Seq, Payload) when is_integer(Id), Id >= 0, Id < 16#FFFF,
    is_integer(Seq), Seq >= 0, Seq < 16#FFFF, is_binary(Payload) ->

    Echo = case Family of
        inet -> echo;
        inet6 -> echo_request
    end,

    packet(Family, [
        {type, Echo},
        {id, Id},
        {sequence, Seq}
    ], Payload).


% Default ICMP echo payload
payload(echo) ->
    {Mega,Sec,USec} = erlang:now(),
    <<Mega:32,Sec:32,USec:32, (list_to_binary(lists:seq($\s, $K)))/binary>>.

% Set the TTL on a socket
set_ttl(FD, inet, TTL) ->
    procket:setsockopt(FD, ?IPPROTO_IP, ip_ttl(), <<TTL:32/native>>);
set_ttl(FD, inet6, TTL) ->
    procket:setsockopt(FD, ?IPPROTO_IPV6, ipv6_unicast_hops(), <<TTL:32/native>>).

% Get the socket TTL
get_ttl(FD, inet) ->
    case procket:getsockopt(FD, ?IPPROTO_IP, ip_ttl(), <<0:32>>) of
        {ok, <<TTL:32/native>>} -> {ok, TTL};
        Error -> Error
    end;
get_ttl(FD, inet6) ->
    case procket:getsockopt(FD, ?IPPROTO_IPV6, ipv6_unicast_hops(), <<0:32>>) of
        {ok, <<TTL:32/native>>} -> {ok, TTL};
        Error -> Error
    end.

%%-------------------------------------------------------------------------
%%% Internal Functions
%%-------------------------------------------------------------------------

%%
%% ping
%%
addr_list(Family, Hosts, false, Multi) ->
    addr_list0(Family, Hosts, Multi);
addr_list(Family, Hosts, true, Multi) ->
    resdedup(addr_list0(Family, Hosts, Multi)).

resdedup(List) ->
    resdedup0(lists:keysort(3, List)).
resdedup0([{ok, _, IP} = A, {ok, _, IP} | List]) ->
    resdedup0([A | List]);
resdedup0([A|List]) ->
    [A | resdedup0(List)];
resdedup0([]) ->
    [].

addr_list0(Family, Hosts, true) ->
    [ begin
          {ok, Host, Ips} = parse(Family, Host),
          [ {ok, Host, Ip} || Ip <- Ips ]
      end || Host <- Hosts ];
addr_list0(Family, Hosts, false) ->
    [ begin
          {ok, Host, [IP|_]} = parse(Family, Host),
          {ok, Host, IP}
      end || Host <- Hosts ].

parse(Addr) ->
    parse(inet, Addr).

parse(Family, Addr) when is_list(Addr) ->
    parse_or_resolve(Family, Addr, inet_parse:address(Addr));
parse(_Family, Addr) when is_tuple(Addr) ->
    {ok, Addr, [Addr]}.

parse_or_resolve(_Family, Addr, {ok, IP}) ->
    {ok, Addr, [IP]};
parse_or_resolve(Family, Addr, {error, einval}) ->
    case inet:gethostbyname(Addr, Family) of
        {ok, #hostent{h_addr_list = IPs}} ->
            {ok, Addr, lists:usort(IPs)};
        _ ->
            [ {error, Addr, nxdomain} ]
    end.

ping_reply(Hosts, #ping_opt{s = Socket, timeout = Timeout} = Opt) ->
    Pid = self(),
    TRef = erlang:send_after(Timeout, Pid, {icmp, Socket, timeout}),
    ping_loop(Hosts, [], Opt#ping_opt{tref = TRef}).

ping_loop([], Acc, #ping_opt{tref = TRef}) ->
    erlang:cancel_timer(TRef),
    {[], Acc};
ping_loop(Hosts, Acc, #ping_opt{
        tref = TRef,
        s = Socket,
        id = Id,
        timestamp = Timestamp
    } = Opt) ->
    receive

        % IPv4 ICMP Echo Reply
        {icmp, Socket, {_,_,_,_} = Reply, TTL,
            <<?ICMP_ECHOREPLY:8, 0:8, _Checksum:16, Id:16, Seq:16, Data/binary>>} ->
            {Elapsed, Payload} = case Timestamp of
                true ->
                    <<Mega:32, Sec:32, USec:32, Data1/binary>> = Data,
                    {timer:now_diff(now(), {Mega,Sec,USec}) div 1000, Data1};
                false ->
                    {0, Data}
            end,
            {Hosts2, Result} = case lists:keytake(Seq, 4, Hosts) of
                {value, {ok, Addr, Address, Seq}, NHosts} ->
                    {NHosts, [{ok, Addr, Address, Reply, {Id, Seq, TTL, Elapsed}, Payload}|Acc]};
                false ->
                    {Hosts, Acc}
            end,
            ping_loop(Hosts2, Result, Opt);

        % IPv4 ICMP Error
        {icmp, Socket, {_,_,_,_} = Reply, TTL, <<Type:8, Code:8, _Checksum1:16, _Unused:32,
                                            4:4, 5:4, _ToS:8, _Len:16, _Id:16, 0:1, _DF:1, _MF:1,
                                            _Off:13, _TTL:8, ?IPPROTO_ICMP:8, _Sum:16,
                                            _SA1:8, _SA2:8, _SA3:8, _SA4:8,
                                            DA1:8, DA2:8, DA3:8, DA4:8,
                                            ?ICMP_ECHO:8, 0:8, _Checksum2:16, Id:16, Seq:16,
                                            _/binary>> = Data} ->
            <<_ICMPHeader:8/bytes, Payload/binary>> = Data,
            DA = {DA1,DA2,DA3,DA4},
            {Hosts2, Result} = case lists:keytake(Seq, 4, Hosts) of
                {value, {ok, Addr, DA, Seq}, NHosts} ->
                    {NHosts, [{error, icmp_message:code({Type, Code}), Addr, DA, Reply, {Id, Seq, TTL, undefined}, Payload}|Acc]};
                false ->
                    {Hosts, Acc}
            end,
            ping_loop(Hosts2, Result, Opt);

        % IPv6 ICMP Echo Reply
        {icmp, Socket, {_,_,_,_,_,_,_,_} = Reply, TTL,
            <<?ICMP6_ECHO_REPLY:8, 0:8, _Checksum:16, Id:16, Seq:16, Data/binary>>} ->
            {Elapsed, Payload} = case Timestamp of
                true ->
                    <<Mega:32, Sec:32, USec:32, Data1/binary>> = Data,
                    {timer:now_diff(now(), {Mega,Sec,USec}) div 1000, Data1};
                false ->
                    {0, Data}
            end,
            {Hosts2, Result} = case lists:keytake(Seq, 4, Hosts) of
                {value, {ok, Addr, Address, Seq}, NHosts} ->
                    {NHosts, [{ok, Addr, Address, Reply, {Id, Seq, TTL, Elapsed}, Payload}|Acc]};
                false ->
                    {Hosts, Acc}
            end,
            ping_loop(Hosts2, Result, Opt);

        % IPv6 ICMP Error
        {icmp, Socket, {_,_,_,_,_,_,_,_} = Reply, TTL, <<Type:8, Code:8, _Checksum1:16, _Unused:32,
                    6:4, _Class:8, _Flow:20,
                    _Len:16, ?IPPROTO_ICMPV6:8, _Hop:8,
                    _SA1:16, _SA2:16, _SA3:16, _SA4:16, _SA5:16, _SA6:16, _SA7:16, _SA8:16,
                    DA1:16, DA2:16, DA3:16, DA4:16, DA5:16, DA6:16, DA7:16, DA8:16,
                    ?ICMP6_ECHO_REQUEST:8, 0:8, _Checksum2:16, Id:16, Seq:16,
                    _/binary>> = Data} ->
            <<_ICMPHeader:8/bytes, Payload/binary>> = Data,
            DA = {DA1,DA2,DA3,DA4,DA5,DA6,DA7,DA8},
            {value, {ok, Addr, DA, Seq}, Hosts2} = lists:keytake(Seq, 4, Hosts),
            {Hosts2, Result} = case lists:keytake(Seq, 4, Hosts) of
                {value, {ok, Addr, DA, Seq}, NHosts} ->
                    {NHosts, [{error, icmp_message:code({Type, Code}), Addr, DA, Reply, {Id, Seq, TTL, undefined}, Payload}|Acc]};
                false ->
                    {Hosts, Acc}
            end,
            ping_loop(Hosts2, Result, Opt);

        % IPv4/IPv6 timeout on socket
        {icmp, Socket, timeout} ->
            erlang:cancel_timer(TRef),
            Timeouts = [ {error, timeout, Addr, IP} || {ok, Addr, IP, _Seq} <- Hosts ],
            {Timeouts, Acc}
    end.

% TTL
ip_ttl() ->
    case os:type() of
        {unix, linux} -> 2;
        {unix, _} -> 4
    end.

ipv6_unicast_hops() ->
    case os:type() of
        {unix, linux} -> 16;
        {unix, _} -> 4
    end.

icmp6_filter() -> 1.

% IPv6 ICMP filtering
%
% Linux reverses the meaining macros in RFC3542
icmp6_filter_setpassall() ->
    case erlang:system_info(os_type) of
        {unix, linux} ->
            <<0:256>>;
        {unix,_} ->
            <<16#ff, 16#ff, 16#ff, 16#ff, 16#ff, 16#ff, 16#ff, 16#ff,
              16#ff, 16#ff, 16#ff, 16#ff, 16#ff, 16#ff, 16#ff, 16#ff,
              16#ff, 16#ff, 16#ff, 16#ff, 16#ff, 16#ff, 16#ff, 16#ff,
              16#ff, 16#ff, 16#ff, 16#ff, 16#ff, 16#ff, 16#ff, 16#ff>>
    end.

icmp6_filter_setblockall() ->
    case erlang:system_info(os_type) of
        {unix, linux} ->
            <<16#ff, 16#ff, 16#ff, 16#ff, 16#ff, 16#ff, 16#ff, 16#ff,
              16#ff, 16#ff, 16#ff, 16#ff, 16#ff, 16#ff, 16#ff, 16#ff,
              16#ff, 16#ff, 16#ff, 16#ff, 16#ff, 16#ff, 16#ff, 16#ff,
              16#ff, 16#ff, 16#ff, 16#ff, 16#ff, 16#ff, 16#ff, 16#ff>>;
        {unix, _} ->
            <<0:256>>
    end.

%#define ICMP6_FILTER_SETPASS(type, filterp) \
%            (((filterp)->icmp6_filt[(type) >> 5]) |= (1 << ((type) & 31)))
icmp6_filter_setpass(Type0, <<_:256>> = Filter) ->
    Type = icmp6_message:type_to_uint8(Type0),
    Offset = Type bsr 5,
    Value = 1 bsl (Type band 31),
    Fun = case erlang:system_info(os_type) of
        {unix, linux} ->
            fun(N) -> N band bnot Value end;
        {unix, _} ->
            fun(N) -> N bor Value end
    end,
    array_set(Offset, Fun, Filter).


%#define ICMP6_FILTER_SETBLOCK(type, filterp) \
%            (((filterp)->icmp6_filt[(type) >> 5]) &= ~(1 << ((type) & 31)))
icmp6_filter_setblock(Type0, <<_:256>> = Filter) ->
    Type = icmp6_message:type_to_uint8(Type0),
    Offset = Type bsr 5,
    Value = 1 bsl (Type band 31),
    Fun = case erlang:system_info(os_type) of
        {unix, linux} ->
            fun(N) -> N bor Value end;
        {unix, _} ->
            fun(N) -> N band bnot Value end
    end,
    array_set(Offset, Fun, Filter).

%#define ICMP6_FILTER_WILLPASS(type, filterp) \
%            ((((filterp)->icmp6_filt[(type) >> 5]) & (1 << ((type) & 31))) != 0)
icmp6_filter_willpass(Type0, <<_:256>> = Filter) ->
    Type = icmp6_message:type_to_uint8(Type0),
    Offset = Type bsr 5,
    Value = 1 bsl (Type band 31),
    El = array_get(Offset, Filter),
    case erlang:system_info(os_type) of
        {unix, linux} -> El band Value =:= 0;
        {unix, _} -> El band Value =/= 0
    end.

%#define ICMP6_FILTER_WILLBLOCK(type, filterp) \
%            ((((filterp)->icmp6_filt[(type) >> 5]) & (1 << ((type) & 31))) == 0)
icmp6_filter_willblock(Type0, <<_:256>> = Filter) ->
    Type = icmp6_message:type_to_uint8(Type0),
    Offset = Type bsr 5,
    Value = 1 bsl (Type band 31),
    El = array_get(Offset, Filter),
    case erlang:system_info(os_type) of
        {unix, linux} -> El band Value =/= 0;
        {unix, _} -> El band Value =:= 0
    end.

% Offset starts at 0
array_set(Offset, Fun, Bin) ->
    Array = array:from_list([ N || <<N:4/native-unsigned-integer-unit:8>> <= Bin ]),
    Value = Fun(array:get(Offset, Array)),
    << <<N:4/native-unsigned-integer-unit:8>> ||
        N <- array:to_list(array:set(Offset, Value, Array))>>.

array_get(Offset, Bin) ->
    Array = array:from_list([ N || <<N:4/native-unsigned-integer-unit:8>> <= Bin ]),
    array:get(Offset, Array).

flush_events(Ref) ->
    receive
        {icmp, Ref, _Addr, _TTL, _Data} ->
            flush_events(Ref)
    after
        0 -> ok
    end.
