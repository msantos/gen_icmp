%% Copyright (c) 2010, Michael Santos <michael.santos@gmail.com>
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
-include("epcap_net.hrl").

-define(SERVER, ?MODULE).

-define(PING_TIMEOUT, 5000).

-export([open/0, open/2, close/1, send/3, controlling_process/2, setopts/2]).
-export([recv/2, recv/3]).
-export([ping/1, ping/2, ping/3]).
-export([
        echo/2, echo/3,
        type/2,
        packet/2
    ]).

-export([start_link/2]).
%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
	 terminate/2, code_change/3]).

-record(state, {
        pid,        % caller PID
        raw,        % raw socket
        s           % udp socket
}).


%%-------------------------------------------------------------------------
%%% API
%%-------------------------------------------------------------------------
open() ->
    open([], []).
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

ping(Host) ->
    ping(Host, []).

ping(Host, Options) when is_tuple(Host) ->
    ping([Host], Options);
ping([Char|_] = Host, Options) when is_integer(Char) ->
    ping([Host], Options);
ping(Hosts, Options) ->
    {ok, Socket} = gen_icmp:open(),
    Res = ping(Socket, Hosts, Options),
    gen_icmp:close(Socket),
    Res.

ping(Socket, Hosts, Options) when is_pid(Socket), is_list(Hosts), is_list(Options) ->
    Id = proplists:get_value(id, Options, erlang:phash2(self(), 16#FFFF)),
    Seq = proplists:get_value(sequence, Options, 0),
    Data = proplists:get_value(data, Options, payload(echo)),
    Timeout = proplists:get_value(timeout, Options, ?PING_TIMEOUT),
    Addresses = addr_list(Hosts),
    [ spawn(fun() -> gen_icmp:send(Socket, Addr, gen_icmp:echo(Id, Seq, Data)) end) || Addr <- Addresses ],
    Response = ping_reply(Socket, Addresses, Id, Seq, Timeout),
    ping_timeout(Addresses, Response).


%%-------------------------------------------------------------------------
%%% Callbacks
%%-------------------------------------------------------------------------
start_link(RawOpts, SockOpts) ->
    Pid = self(),
    gen_server:start_link(?MODULE, [Pid, RawOpts, SockOpts], []).

init([Pid, RawOpts, SockOpts]) ->
    {ok, FD} = procket:listen(0, RawOpts ++ [{protocol, icmp}, {type, raw}, {family, inet}]),
    {ok, Socket} = gen_udp:open(0, SockOpts ++ [binary, {fd, FD}]),
    {ok, #state{
            pid = Pid,
            raw = FD,
            s = Socket
        }}.

handle_call(close, {Pid,_}, #state{pid = Pid, s = Socket} = State) ->
    {stop, normal, gen_udp:close(Socket), State};
handle_call({send, IP, Packet}, _From, #state{s = Socket} = State) ->
    {reply, gen_udp:send(Socket, IP, 0, Packet), State};
handle_call({recv, Length, Timeout}, {Pid,_}, #state{pid = Pid, s = Socket} = State) ->
    {reply, gen_udp:recv(Socket, Length, Timeout), State};
handle_call({controlling_process, Pid}, {Owner,_}, #state{pid = Owner} = State) ->
    {reply, ok, State#state{pid = Pid}};
handle_call({setopts, Options}, {Pid,_}, #state{pid = Pid, s = Socket} = State) ->
    {reply, inet:setopts(Socket, Options), State};

handle_call(Request, From, State) ->
    error_logger:info_report([{call, Request}, {from, From}, {state, State}]),
    {reply, error, State}.

handle_cast(Msg, State) ->
    error_logger:info_report([{cast, Msg}, {state, State}]),
    {noreply, State}.

handle_info({udp, Socket, Saddr, 0,
        <<4:4, HL:4, _ToS:8, _Len:16, _Id:16, 0:1, _DF:1, _MF:1,
          _Off:13, _TTL:8, ?IPPROTO_ICMP:8, _Sum:16,
          SA1:8, SA2:8, SA3:8, SA4:8,
          _DA1:8, _DA2:8, _DA3:8, _DA4:8,
          Data/binary>>}, #state{pid = Pid, s = Socket} = State) when Saddr == {SA1,SA2,SA3,SA4} ->
    Opt = case (HL-5)*4 of
        N when N > 0 -> N;
        _ -> 0
    end,
    <<_:Opt/bits, Payload/bits>> = Data,
    Pid ! {icmp, self(), Saddr, Payload},
    {noreply, State};
handle_info(Info, State) ->
    error_logger:info_report([{info, Info}, {state, State}]),
    {noreply, State}.

terminate(_Reason, #state{raw = Socket}) ->
    procket:close(Socket),
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.


%%-------------------------------------------------------------------------
%%% Utility Functions
%%-------------------------------------------------------------------------

%% Create an ICMP packet
packet(Header, Payload) when is_list(Header), is_binary(Payload) ->
    Default = #icmp{},

    Type = type(proplists:get_value(type, Header, Default#icmp.type)),
    Code = code(proplists:get_value(code, Header, Default#icmp.code)),

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
packet(#icmp{} = Header, Payload) when is_binary(Payload) ->
    Sum = epcap_net:makesum(list_to_binary([
                epcap_net:icmp(Header),
                Payload
            ])),

    list_to_binary([
        epcap_net:icmp(Header#icmp{checksum = Sum}),
        Payload
    ]).

echo(Id, Seq) ->
    % Pad packet to 64 bytes
    echo(Id, Seq, payload(echo)).
echo(Id, Seq, Payload) when is_integer(Id), Id >= 0, Id < 16#FFFF,
    is_integer(Seq), Seq >= 0, Seq < 16#FFFF, is_binary(Payload) ->
    {Mega,Sec,USec} = erlang:now(),
    packet([
        {type, ?ICMP_ECHO},
        {code, 0},
        {id, Id},
        {sequence, Seq}
    ], <<Mega:32,Sec:32,USec:32, Payload/binary>>).



%%-------------------------------------------------------------------------
%%% Internal Functions
%%-------------------------------------------------------------------------
type(?ICMP_DEST_UNREACH, 0) -> net_unreachable;
type(?ICMP_DEST_UNREACH, 1) -> host_unreachable;
type(?ICMP_DEST_UNREACH, 2) -> protocol_unreachable;
type(?ICMP_DEST_UNREACH, 3) -> port_unreachable;
type(?ICMP_DEST_UNREACH, 4) -> frag_needed;
type(?ICMP_DEST_UNREACH, 5) -> source_route_failed;

type(?ICMP_TIME_EXCEEDED, _Code) -> time_exceeded;
type(?ICMP_PARAMETERPROB, _Code) -> parameter_problem;
type(?ICMP_REDIRECT, _Code) -> redirect;
type(?ICMP_ECHO, _Code) -> echo;
type(?ICMP_ECHOREPLY, _Code) -> echoreply;
type(Type, Code) -> {unknown, Type, Code}.

payload(echo) ->
    list_to_binary(lists:seq($\s, $K)).

%%
%% ping
%%
addr_list(Hosts) ->
    sets:to_list(sets:from_list([ parse(Host) || Host <- Hosts ])).

parse(Addr) when is_list(Addr) ->
    parse_or_resolve(Addr, inet_parse:address(Addr));
parse(Addr) when is_tuple(Addr) ->
    Addr.

parse_or_resolve(_Addr, {ok, IP}) ->
    IP;
parse_or_resolve(Addr, {error, einval}) ->
    case inet_res:gethostbyname(Addr) of
        {ok, #hostent{h_addr_list = IPs}} ->
            hd(IPs);
        _ ->
            throw({badarg, Addr})
    end.

ping_timeout(A,B) ->
    B1 = [ X || {_,X,_} <- B ],
    B ++ [ {{error, timeout}, X} || X <- A -- B1 ].

ping_reply(Socket, Hosts, Id, Seq, Timeout) ->
    Pid = self(),
    TRef = erlang:send_after(Timeout, Pid, {icmp, timeout}),
    ping_loop(Socket, TRef, Hosts, [], Id, Seq).

ping_loop(_Socket, TRef, [], Acc, _Id, _Seq) ->
    erlang:cancel_timer(TRef),
    Acc;
ping_loop(Socket, TRef, Hosts, Acc, Id, Seq) ->
    receive
        {icmp, Socket, Address,
            <<?ICMP_ECHOREPLY:8, 0:8, _Checksum:16, Id:16, Seq:16, Mega:32, Sec:32, USec:32, Data/binary>>} ->
            T = timer:now_diff(now(), {Mega,Sec,USec}),
            ping_loop(Socket, TRef, Hosts -- [Address], [{ok, Address, {{Id, Seq, T}, Data}}|Acc], Id, Seq);
        {icmp, Socket, Saddr,
            <<Type:8, Code:8, _Checksum1:16, _Unused:32,
            4:4, 5:4, _ToS:8, _Len:16, _Id:16, 0:1, _DF:1, _MF:1,
            _Off:13, _TTL:8, ?IPPROTO_ICMP:8, _Sum:16,
            SA1:8, SA2:8, SA3:8, SA4:8,
            DA1:8, DA2:8, DA3:8, DA4:8,
            ?ICMP_ECHO:8, 0:8, _Checksum2:16, Id:16, Seq:16,
            _/binary>> = Data} when Saddr == {SA1,SA2,SA3,SA4} ->
            <<_:8/bytes, Payload/binary>> = Data,
            DA = {DA1,DA2,DA3,DA4},
            ping_loop(Socket, TRef, Hosts -- [DA],
                [{{error, gen_icmp:type(Type, Code)}, DA, {{Id, Seq}, Payload}}|Acc],
                Id, Seq);
        {icmp, timeout} ->
            ping_loop(Socket, TRef, [], Acc, Id, Seq)
    end.


