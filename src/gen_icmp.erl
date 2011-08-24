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
-module(gen_icmp).
-behaviour(gen_server).
-include_lib("kernel/include/inet.hrl").
-include("pkt.hrl").

-define(SERVER, ?MODULE).

-define(PING_TIMEOUT, 5000).

-export([open/0, open/2, close/1, send/3, controlling_process/2, setopts/2]).
-export([recv/2, recv/3]).
-export([ping/1, ping/2, ping/3]).
-export([
        echo/2, echo/3,
        type/1, code/1,
        packet/2,
        parse/1
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

-record(ping_opt, {
        s,
        id,
        sequence,
        timeout,
        tref,
        timestamp = true
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
    Timestamp = proplists:get_value(timestamp, Options, true),
    Addresses = addr_list(Hosts),
    [ spawn(fun() -> gen_icmp:send(Socket, Addr, gen_icmp:echo(Id, Seq, Data)) end) || Addr <- Addresses ],
    Response = ping_reply(Addresses, #ping_opt{
            s = Socket,
            id = Id,
            sequence = Seq,
            timeout = Timeout,
            timestamp = Timestamp
        }),
    ping_timeout(Addresses, Response).


%%-------------------------------------------------------------------------
%%% Callbacks
%%-------------------------------------------------------------------------
start_link(RawOpts, SockOpts) ->
    Pid = self(),
    gen_server:start_link(?MODULE, [Pid, RawOpts, SockOpts], []).

init([Pid, RawOpts, SockOpts]) ->
    process_flag(trap_exit, true),

    {ok, FD} = case proplists:get_value(setuid, RawOpts, true) of
        true ->
            procket:open(0, RawOpts ++ [{protocol, icmp}, {type, raw}, {family, inet}]);
        false ->
            procket:socket(inet, raw, icmp)
    end,
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
    Reply = case gen_udp:recv(Socket, Length, Timeout) of
        {ok, {Address, _Port, Packet}} -> {ok, {Address, Packet}};
        N -> N
    end,
    {reply, Reply, State};
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

    Type = type_to_uint8(proplists:get_value(type, Header, Default#icmp.type)),
    Code = code_to_uint8(proplists:get_value(code, Header, Default#icmp.code)),

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
    Sum = pkt:makesum(list_to_binary([
                pkt:icmp(Header),
                Payload
            ])),

    list_to_binary([
        pkt:icmp(Header#icmp{checksum = Sum}),
        Payload
    ]).

type_to_uint8(Type) when is_integer(Type) -> Type;
type_to_uint8(Type) when is_atom(Type) -> type(Type).

code_to_uint8(Code) when is_integer(Code) -> Code;
code_to_uint8(Code) when is_atom(Code) -> code(Code).

echo(Id, Seq) ->
    % Pad packet to 64 bytes
    echo(Id, Seq, payload(echo)).
echo(Id, Seq, Payload) when is_integer(Id), Id >= 0, Id < 16#FFFF,
    is_integer(Seq), Seq >= 0, Seq < 16#FFFF, is_binary(Payload) ->
    packet([
        {type, echo},
        {id, Id},
        {sequence, Seq}
    ], Payload).


%%
%% ICMP control message: types
%%
type(?ICMP_ECHOREPLY) -> echoreply;
type(?ICMP_DEST_UNREACH) -> dest_unreach;
type(?ICMP_SOURCE_QUENCH) -> source_quench;
type(?ICMP_REDIRECT) -> redirect;
type(?ICMP_ECHO) -> echo;
type(?ICMP_TIME_EXCEEDED) -> time_exceeded;
type(?ICMP_PARAMETERPROB) -> parameterprob;
type(?ICMP_TIMESTAMP) -> timestamp;
type(?ICMP_TIMESTAMPREPLY) -> timestampreply;
type(?ICMP_INFO_REQUEST) -> info_request;
type(?ICMP_INFO_REPLY) -> info_reply;
type(?ICMP_ADDRESS) -> address;
type(?ICMP_ADDRESSREPLY) -> addressreply;

type(echoreply) -> ?ICMP_ECHOREPLY;
type(dest_unreach) -> ?ICMP_DEST_UNREACH;
type(source_quench) -> ?ICMP_SOURCE_QUENCH;
type(redirect) -> ?ICMP_REDIRECT;
type(echo) -> ?ICMP_ECHO;
type(time_exceeded) -> ?ICMP_TIME_EXCEEDED;
type(parameterprob) -> ?ICMP_PARAMETERPROB;
type(timestamp) -> ?ICMP_TIMESTAMP;
type(timestampreply) -> ?ICMP_TIMESTAMPREPLY;
type(info_request) -> ?ICMP_INFO_REQUEST;
type(info_reply) -> ?ICMP_INFO_REPLY;
type(address) -> ?ICMP_ADDRESS;
type(addressreply) -> ?ICMP_ADDRESSREPLY.

%%
%% ICMP control message: codes
%%

% destination unreachable
code(unreach_net) -> ?ICMP_UNREACH_NET;
code(unreach_host) -> ?ICMP_UNREACH_HOST;
code(unreach_protocol) -> ?ICMP_UNREACH_PROTOCOL;
code(unreach_port) -> ?ICMP_UNREACH_PORT;
code(unreach_needfrag) -> ?ICMP_UNREACH_NEEDFRAG;
code(unreach_srcfail) -> ?ICMP_UNREACH_SRCFAIL;

% redirect
code(redirect_net) -> ?ICMP_REDIRECT_NET;
code(redirect_host) -> ?ICMP_REDIRECT_HOST;
code(redirect_tosnet) -> ?ICMP_REDIRECT_TOSNET;
code(redirect_toshost) -> ?ICMP_REDIRECT_TOSHOST;

% time_exceeded
code(timxceed_intrans) -> ?ICMP_TIMXCEED_INTRANS;
code(timxceed_reass) -> ?ICMP_TIMXCEED_REASS;

% XXX create a fake code so:
% XXX e.g., code(code({?ICMP_ECHO, 0})) == 0
code(Code) when Code == echoreply; Code == source_quench; Code == echo;
    Code == parameterprob; Code == timestamp; Code == timestampreply;
    Code == info_request; Code == info_reply; Code == address;
    Code == addressreply -> 0;

code({?ICMP_ECHOREPLY, 0}) -> echoreply;

code({?ICMP_DEST_UNREACH, ?ICMP_UNREACH_NET}) -> unreach_net;
code({?ICMP_DEST_UNREACH, ?ICMP_UNREACH_HOST}) -> unreach_host;
code({?ICMP_DEST_UNREACH, ?ICMP_UNREACH_PROTOCOL}) -> unreach_protocol;
code({?ICMP_DEST_UNREACH, ?ICMP_UNREACH_PORT}) -> unreach_port;
code({?ICMP_DEST_UNREACH, ?ICMP_UNREACH_NEEDFRAG}) -> unreach_needfrag;
code({?ICMP_DEST_UNREACH, ?ICMP_UNREACH_SRCFAIL}) -> unreach_srcfail;

code({?ICMP_SOURCE_QUENCH, 0}) -> source_quench;

code({?ICMP_REDIRECT, ?ICMP_REDIRECT_NET}) -> redirect_net;
code({?ICMP_REDIRECT, ?ICMP_REDIRECT_HOST}) -> redirect_host;
code({?ICMP_REDIRECT, ?ICMP_REDIRECT_TOSNET}) -> redirect_tosnet;
code({?ICMP_REDIRECT, ?ICMP_REDIRECT_TOSHOST}) -> redirect_toshost;

code({?ICMP_ECHO, 0}) -> echo;

code({?ICMP_TIME_EXCEEDED, ?ICMP_TIMXCEED_INTRANS}) -> timxceed_intrans;
code({?ICMP_TIME_EXCEEDED, ?ICMP_TIMXCEED_REASS}) -> timxceed_reass;

code({?ICMP_PARAMETERPROB, 0}) -> parameterprob;

code({?ICMP_TIMESTAMP, 0}) -> timestamp;
code({?ICMP_TIMESTAMPREPLY, 0}) -> timestampreply;

code({?ICMP_INFO_REQUEST, 0}) -> info_request;
code({?ICMP_INFO_REPLY, 0}) -> info_reply;

code({?ICMP_ADDRESS, 0}) -> address;
code({?ICMP_ADDRESSREPLY, 0}) -> addressreply;

code({Type, Code}) -> {unknown, type(Type), code(Code)}.


% Default ICMP echo payload
payload(echo) ->
    {Mega,Sec,USec} = erlang:now(),
    <<Mega:32,Sec:32,USec:32, (list_to_binary(lists:seq($\s, $K)))/binary>>.


%%-------------------------------------------------------------------------
%%% Internal Functions
%%-------------------------------------------------------------------------

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
        {ok, #hostent{h_addr_list = [IP|_IPs]}} -> IP;
        _ -> throw({badarg, Addr})
    end.

ping_timeout(A,B) ->
    B1 = [ X || {_,X,_} <- B ],
    B ++ [ {{error, timeout}, X} || X <- A -- B1 ].

ping_reply(Hosts, #ping_opt{s = Socket, timeout = Timeout} = Opt) ->
    Pid = self(),
    TRef = erlang:send_after(Timeout, Pid, {icmp, Socket, timeout}),
    ping_loop(Hosts, [], Opt#ping_opt{tref = TRef}).

ping_loop([], Acc, #ping_opt{tref = TRef}) ->
    erlang:cancel_timer(TRef),
    Acc;
ping_loop(Hosts, Acc, #ping_opt{
        s = Socket,
        id = Id,
        sequence = Seq,
        timestamp = Timestamp
    } = Opt) ->
    receive
        {icmp, Socket, Address,
            <<?ICMP_ECHOREPLY:8, 0:8, _Checksum:16, Id:16, Seq:16, Data/binary>>} ->
            {Elapsed, Payload} = case Timestamp of
                true ->
                    <<Mega:32, Sec:32, USec:32, Data1/binary>> = Data,
                    {timer:now_diff(now(), {Mega,Sec,USec}), Data1};
                false ->
                    {0, Data}
            end,
            ping_loop(Hosts -- [Address], [{ok, Address, {{Id, Seq, Elapsed}, Payload}}|Acc], Opt);
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
            ping_loop(Hosts -- [DA], [{{error, code({Type, Code})}, DA, {{Id, Seq}, Payload}}|Acc],
                Opt);
        {icmp, Socket, timeout} ->
            ping_loop([], Acc, Opt)
    end.
