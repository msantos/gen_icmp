%%% @copyright 2010-2023 Michael Santos <michael.santos@gmail.com>
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

-module(gen_icmp).
-behaviour(gen_server).
-include_lib("kernel/include/inet.hrl").
-include_lib("pkt/include/pkt.hrl").

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
    parse/1, parse/2,

    gettime/0,
    timediff/1, timediff/2
]).
-export([addr_list/3]).

-export([start_link/2, start/2]).
%% gen_server callbacks
-export([
    init/1,
    handle_call/3,
    handle_cast/2,
    handle_info/2,
    terminate/2,
    code_change/3
]).

-type uint8_t() :: 0..16#ff.
-type uint16_t() :: 0..16#ffff.

-type int32_t() :: -16#7fffffff..16#7fffffff.

-type fd() :: int32_t().
-type socket() :: pid().
-type icmp6_filter() :: <<_:256>>.

% ping details
-type id() :: uint16_t().
-type sequence() :: uint16_t().
-type ttlx() :: uint8_t().
-type elapsed() :: int32_t() | undefined.

-export_type([
    uint8_t/0,
    uint16_t/0,

    int32_t/0,

    fd/0,
    socket/0,
    icmp6_filter/0,

    id/0,
    sequence/0,
    ttlx/0,
    elapsed/0
]).

-record(state, {
    % Protocol family (inet, inet6)
    family = inet :: inet | inet6,
    % caller PID
    pid :: pid(),
    % socket file descriptor
    fd :: fd(),
    % udp socket
    s :: gen_udp:socket()
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
    saddr = {0, 0, 0, 0, 0, 0, 0, 0},
    daddr = {0, 0, 0, 0, 0, 0, 0, 0},
    len = 0,
    next = ?IPPROTO_ICMPV6,
    h = #icmp6{}
}).

%% @doc Open an ICMP socket
%%
%% By default, the ICMP socket is opened in {active,false} mode. No
%% packets will be received by the socket. setopts/2 can be used
%% to place the socket in {active,true} mode.
%%
%% gen_icmp first attempts to natively open the socket and falls
%% back to forking the setuid helper program if beam does not have
%% the appropriate privileges. Privileges to open a raw socket can
%% be given by, for example, running as root or, on Linux, granting
%% the CAP_NET_RAW capability to beam:
%%
%%     setcap cap_net_raw=ep /usr/local/lib/erlang/erts-5.8.3/bin/beam.smp
%%
%% Only the owning process will receive ICMP packets (see
%% controlling_process/2 to change the owner). The process owning the
%% raw socket will receive all ICMP packets sent to the host.
%%
%% Messages sent to the controlling process are:
%%
%% {icmp, Socket, Address, TTL, Packet}
%%
%% Where:
%%
%% * Socket is the pid of the gen_icmp process
%%
%% * Address is a tuple representing the IPv4 or IPv6 source address
%%
%% * TTL: IPv4: TTL taken from the IP header
%%
%% * TTL: IPv6: the socket's hop limit returned from
%%   getsockopt(IPV6_UNICAST_HOPS) (this is not the packet's
%%   TTL, it is the socket's max TTL)
%%
%% * Packet is the complete ICMP packet including the ICMP headers
%%
%% == Examples ==
%%
%% ```
%% 1> gen_icmp:open().
%% {ok,<0.299.0>}
%% '''
-spec open() -> {ok, socket()} | {error, system_limit | inet:posix()}.
open() ->
    open([], []).

%% @doc Open an ICMP socket with raw socket options
%%
%% See the https://github.com/msantos/procket for the raw socket options
%% and for instructions on setting up the setuid helper.
%%
%% == Examples ==
%%
%% ```
%% 1> gen_icmp:open([{ttl, 1}, inet6]).
%% {ok,<0.302.0>}
%% '''
-spec open(proplists:proplist()) -> {ok, socket()} | {error, system_liimt | inet:posix()}.
open(RawOpts) ->
    open(RawOpts, []).

%% @doc Open an ICMP socket with options
%%
%% == Examples ==
%%
%% ```
%% 1> gen_icmp:open([{ttl, 1}, inet6], [list]).
%% {ok,<0.302.0>}
%% '''
-spec open(proplists:proplist(), [inet:inet_backend() | gen_udp:open_option()]) ->
    {ok, socket()} | {error, system_liimt | inet:posix()}.
open(RawOpts, SockOpts) ->
    start_link(RawOpts, SockOpts).

%% @doc Close the ICMP socket
%%
%% == Examples ==
%%
%% ```
%% 1> {ok, S} = gen_icmp:open().
%% {ok,<0.224.0>}
%% 2> gen_icmp:close(S).
%% ok
%% '''
-spec close(socket()) -> ok.
close(Socket) when is_pid(Socket) ->
    gen_server:call(Socket, close, infinity).

%% @doc Send data via an ICMP socket
%%
%% Like the gen_udp and gen_tcp modules, any process can send ICMP
%% packets but only the owner will receive the responses.
%%
%% == Examples ==
%%
%% ```
%% 1> {ok, S} = gen_icmp:open().
%% {ok,<0.224.0>}
%% 2>gen_icmp:send(S, "google.com", gen_icmp:echo(inet, 0, 0)).
%% ok
%% 3> gen_icmp:recv(S, 1).
%% {ok,{{142,251,32,78},
%%      <<69,0,0,84,0,0,0,0,116,1,214,38,142,251,32,78,100,115,
%%             92,198,0,0,19,125,0,...>>}}
%% 4> gen_icmp:close(S).
%% ok
%% '''
-spec send(
    socket(),
    {inet:ip_address(), inet:port_number()}
    | inet:family_address()
    | socket:sockaddr_in()
    | socket:sockaddr_in6(),
    iodata()
) -> ok | {error, not_owner | inet:posix()}.
send(Socket, Address, Packet) when is_pid(Socket) ->
    gen_server:call(Socket, {send, Address, Packet}, infinity).

%% @doc Read data from an ICMP socket
%%
%% This function receives a packet from a socket in passive mode.
%%
%% == Examples ==
%%
%% ```
%% 1> {ok, S} = gen_icmp:open().
%% {ok,<0.224.0>}
%% 2>gen_icmp:send(S, "google.com", gen_icmp:echo(inet, 0, 0)).
%% ok
%% 3> gen_icmp:recv(S, 1).
%% {ok,{{142,251,32,78},
%%      <<69,0,0,84,0,0,0,0,116,1,214,38,142,251,32,78,100,115,
%%             92,198,0,0,19,125,0,...>>}}
%% 4> gen_icmp:close(S).
%% ok
%% '''
-spec recv(socket(), non_neg_integer()) ->
    {ok, inet:ip_address() | inet:returned_non_ip_address(), string() | binary()}
    | {error, not_owner | timeout | inet:posix()}.
recv(Socket, Length) ->
    recv(Socket, Length, infinity).

%% @doc Read data from an ICMP socket with timeout
%%
%% The optional Timeout parameter specifies a timeout in
%% milliseconds. The default value is infinity.
%%
%% == Examples ==
%%
%% ```
%% 1> {ok, S} = gen_icmp:open().
%% {ok,<0.299.0>}
%% 2> gen_icmp:send(S, "google.com", gen_icmp:echo(inet, 0, 0)).
%% ok
%% 3> gen_icmp:recv(S, 1, 5000).
%% {ok,{{142,251,41,78},
%%           <<69,0,0,84,0,0,0,0,116,1,205,38,142,251,41,78,100,115,
%%                    92,198,0,0,100,77,0,...>>}}
%% 4> gen_icmp:recv(S, 1, 5000).
%% {error,timeout}
%% 5> gen_icmp:close(S).
%% ok
%% '''
-spec recv(socket(), non_neg_integer(), timeout()) ->
    {ok, inet:ip_address() | inet:returned_non_ip_address(), string() | binary()}
    | {error, not_owner | timeout | inet:posix()}.
recv(Socket, Length, Timeout) ->
    gen_server:call(Socket, {recv, Length, Timeout}, infinity).

%% @doc Change the controlling process of the ICMP socket
%%
%% Change the process owning the socket. Allows another process to
%% receive the ICMP responses.
-spec controlling_process(socket(), pid()) -> ok.
controlling_process(Socket, Pid) when is_pid(Socket), is_pid(Pid) ->
    gen_server:call(Socket, {controlling_process, Pid}, infinity).

%% @doc Set socket options
%%
%% For options, see the inet man page. Simply calls inet:setopts/2 on
%% the gen_udp socket.
%%
%% setopts/2 can be used to toggle the socket between passive and
%% active mode.
%%
%% == Examples ==
%%
%% ```
%% {ok, Socket} = gen_icmp:open(), % socket is {active,false}
%% ok = gen_icmp:setopts(Socket, [{active, true}]),
%% % do stuff with the socket
%% ok = gen_icmp:setopts(Socket, [{active, false}]).
%% '''
-spec setopts(socket(), [inet:socket_setopt()]) -> ok | {error, inet:posix()}.
setopts(Socket, Options) when is_pid(Socket), is_list(Options) ->
    gen_server:call(Socket, {setopts, Options}, infinity).

%% @doc Get socket family
%%
%% Returns the socket family: `inet' (IPv4), `inet6' (IPv6)
%%
%% == Examples ==
%%
%% ```
%% 1> {ok, S} = gen_icmp:open([inet6]).
%% {ok,<0.224.0>}
%% 2> gen_icmp:family(S).
%% inet6
%% '''
-spec family(socket()) -> inet | inet6.
family(Socket) when is_pid(Socket) ->
    gen_server:call(Socket, family, infinity).

%% @doc Get underlying file descriptor for socket
%%
%% == Examples ==
%%
%% ```
%% 1> {ok, S} = gen_icmp:open().
%% {ok,<0.221.0>}
%% 2> gen_icmp:getfd(S).
%% 20
%% '''
-spec getfd(socket()) -> fd().
getfd(Socket) when is_pid(Socket) ->
    gen_server:call(Socket, getfd, infinity).

%% @doc Get ICMPv6 filter for a socket
%%
%% Retrieves the ICMPv6 filter for a socket. For ICMPv4
%% sockets, the atom `unsupported' is returned.
%%
%% == Examples ==
%%
%% ```
%% 1> {ok, S} = gen_icmp:open([inet6]).
%% {ok,<0.299.0>}
%% 2> gen_icmp:filter(S).
%% {ok,<<0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
%%       0,0,...>>}
%% '''
-spec filter(socket()) -> {ok, icmp6_filter()} | {error, unsupported | inet:posix()}.
filter(Socket) when is_pid(Socket) ->
    gen_server:call(Socket, filter, infinity).

%% @doc Set ICMPv6 filter for a socket
%%
%% Sets an ICMPv6 filter on a socket. For ICMPv4 sockets, the atom
%% `unsupported' is returned.
%%
%% Filters can be generated by using the icmp6_filter functions.
%%
%% == Examples ==
%%
%% ```
%% 1> {ok, S} = gen_icmp:open([inet6]).
%% {ok,<0.299.0>}
%% 2> gen_icmp:filter(S, gen_icmp:icmp6_filter_setpassall()).
%% ok
%% '''
-spec filter(socket(), icmp6_filter()) -> ok | {error, unsupported | inet:posix()}.
filter(Socket, Filter) when is_pid(Socket) ->
    gen_server:call(Socket, {filter, Filter}, infinity).

%% @doc Send an ICMP ECHO_REQUEST
%%
%% ping/1 is a convenience function to send a single ping
%% packet. The argument to ping/1 can be either a hostname or a
%% list of hostnames.
%%
%% == Examples ==
%%
%% ```
%% 1> gen_icmp:ping("google.com").
%% [{ok,"google.com",
%%      {142,251,41,46},
%%      {142,251,41,46},
%%      {61261,0,116,84},
%%      <<" !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNO">>}]
%% '''
%%
%% @see ping/3
-spec ping(inet:socket_address() | inet:hostname() | [inet:socket_address() | inet:hostname()]) ->
    [
        {ok, inet:socket_address() | inet:hostname(), inet:ip_address(), inet:ip_address(),
            {id(), sequence(), ttlx(), elapsed()}, binary()}
        | {error, unreach_host | timxceed_intrans, [inet:socket_address() | inet:hostname()],
            inet:ip_address(), inet:ip_address(), {id(), sequence(), ttlx(), elapsed()}, binary()}
        | {error, timeout | inet:posix(), [inet:socket_address() | inet:hostname()],
            inet:ip_address()}
    ].
ping(Host) ->
    ping(Host, []).

%% @doc Send an ICMP ECHO_REQUEST with options
%%
%% Ping a host or a list of hosts.
%%
%% == Examples ==
%%
%% ```
%% 1> gen_icmp:ping("google.com", [inet6]).
%% [{ok,"google.com",
%%      {9735,63664,16395,2052,0,0,0,8206},
%%      {9735,63664,16395,2052,0,0,0,8206},
%%      {61261,0,64,53},
%%      <<" !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNO">>}]
%% '''
%%
%% @see ping/3
-spec ping(
    inet:socket_address() | inet:hostname() | [inet:socket_address() | inet:hostname()],
    proplists:proplist()
) ->
    [
        {ok, inet:socket_address() | inet:hostname(), inet:ip_address(), inet:ip_address(),
            {id(), sequence(), ttlx(), elapsed()}, binary()}
        | {error, unreach_host | timxceed_intrans, [inet:socket_address() | inet:hostname()],
            inet:ip_address(), inet:ip_address(), {id(), sequence(), ttlx(), elapsed()}, binary()}
        | {error, timeout | inet:posix(), [inet:socket_address() | inet:hostname()],
            inet:ip_address()}
    ].
ping(Host, Options) when is_tuple(Host) ->
    ping([Host], Options);
ping([Char | _] = Host, Options) when is_integer(Char) ->
    ping([Host], Options);
ping(Hosts, Options) ->
    {ok, Socket} = gen_icmp:open(Options),
    Res = ping(Socket, Hosts, Options),
    gen_icmp:close(Socket),
    Res.

%% @doc Send an ICMP ECHO_REQUEST
%%
%% To prevent the process mailbox from being flooded with ICMP
%% messages, ping/3 will put the socket into `{active,false}' mode
%% after completing.
%%
%% The ping/3 function blocks until either an ICMP ECHO REPLY is
%% received from all hosts or Timeout is reached.
%%
%% Id and sequence are used to differentiate ping responses. Usually,
%% the sequence is incremented for each ping in one run.
%%
%% A list of responses is returned. If the ping was successful,
%% the elapsed time in milliseconds is included (calculated by
%% subtracting the current time from the time we sent in the ICMP
%% ECHO packet and returned to us in the ICMP ECHOREPLY payload)
%% where:
%%
%% * Host: the provided hostname
%%
%% * Address: the resolved IPv4 or IPv6 network address represented
%%   as a 4 or 8-tuple used in the ICMP echo request
%%
%% * ReplyAddr: the IPv4 or IPv6 network address originating the
%%   ICMP echo reply
%%
%% The timeout is set for all ICMP packets and is set after all
%% packets have been sent out.
%%
%% By default only one address per hostname is pinged. To
%% enable pinging all addresses per hostname pass `{multi, true}'
%% to options.
%%
%% A ping payload contains an 8 byte timestamp in microseconds. When
%% creating a custom payload, the first 8 bytes of the ICMP echo
%% reply payload will be used for calculating the elapsed time. To
%% disable this behaviour, use the option {timestamp,false} (the
%% elapsed time in the return value will be set to 0).
%%
%% The timeout defaults to 5 seconds.
%%
%% ICMPv6 sockets can restrict which ICMPv6 types are received by the
%% socket using the filter option.  The filter argument is a binary
%% generated using the icmp6_filter functions described below.
%%
%% The default filter allows: ICMP6_ECHO_REPLY, ICMP6_DST_UNREACH,
%% ICMP6_PACKET_TOO_BIG, ICMP6_TIME_EXCEEDED and ICMP6_PARAM_PROB.
%% Note: ping/3 does not restore the original filter on the socket.
%%
%% == Examples ==
%%
%% ```
%% 1> {ok, S} = gen_icmp:open([inet6]).
%% {ok,<0.299.0>}
%% 2> gen_icmp:ping(S, ["google.com"], []).
%% [{ok,"google.com",
%%      {9735,63664,16395,2051,0,0,0,8206},
%%      {9735,63664,16395,2051,0,0,0,8206},
%%      {61261,0,64,110},
%%      <<" !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNO">>}]
%% 3> gen_icmp:ping(S, ["2001:4860:4860::8888"], []).
%% [{ok,"2001:4860:4860::8888",
%%      {8193,18528,18528,0,0,0,0,34952},
%%      {8193,18528,18528,0,0,0,0,34952},
%%      {61261,0,64,20},
%%      <<" !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNO">>}]
%% 4> gen_icmp:ping(S, ["2001:4860:4860::8888", "google.com"], []).
%% [{ok,"google.com",
%%      {9735,63664,16395,2051,0,0,0,8206},
%%      {9735,63664,16395,2051,0,0,0,8206},
%%      {61261,1,64,23},
%%      <<" !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNO">>},
%%  {ok,"2001:4860:4860::8888",
%%      {8193,18528,18528,0,0,0,0,34952},
%%      {8193,18528,18528,0,0,0,0,34952},
%%      {61261,0,64,23},
%%      <<" !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNO">>}]
%% 5> gen_icmp:close(S).
%% ok
%% '''
-spec ping(socket(), [inet:socket_address() | inet:hostname()], proplists:proplist()) ->
    [
        {ok, inet:socket_address() | inet:hostname(), inet:ip_address(), inet:ip_address(),
            {id(), sequence(), ttlx(), elapsed()}, binary()}
        | {error, unreach_host | timxceed_intrans, [inet:socket_address() | inet:hostname()],
            inet:ip_address(), inet:ip_address(), {id(), sequence(), ttlx(), elapsed()}, binary()}
        | {error, timeout | inet:posix(), [inet:socket_address() | inet:hostname()],
            inet:ip_address()}
    ].
ping(Socket, Hosts, Options) when is_pid(Socket), is_list(Hosts), is_list(Options) ->
    ok = setopts(Socket, [{active, true}]),

    Family = family(Socket),

    Id = proplists:get_value(id, Options, erlang:phash2(self(), 16#FFFF)),
    Seq = proplists:get_value(sequence, Options, 0),
    Data = proplists:get_value(data, Options, payload(echo)),
    Timeout = proplists:get_value(timeout, Options, ?PING_TIMEOUT),
    Timestamp = proplists:get_value(timestamp, Options, true),
    Multi = proplists:get_value(multi, Options, false),

    ICMP6_filter = lists:foldl(
        fun(T, X) ->
            gen_icmp:icmp6_filter_setpass(T, X)
        end,
        gen_icmp:icmp6_filter_setblockall(),
        [
            echo_reply,
            dst_unreach,
            packet_too_big,
            time_exceeded,
            param_prob
        ]
    ),

    Filter = proplists:get_value(filter, Options, ICMP6_filter),

    ok =
        case Family of
            inet6 ->
                filter(Socket, Filter);
            _ ->
                ok
        end,

    Hosts2 = addr_list(Family, Hosts, Multi),

    {Addresses, Errors, _} = lists:foldl(
        fun
            ({ok, Host, Addr}, {NHosts, Nerr, NSeq}) ->
                {[{ok, Host, Addr, NSeq} | NHosts], Nerr, NSeq + 1};
            (Err, {NHosts, Nerr, NSeq}) ->
                {NHosts, [Err | Nerr], NSeq}
        end,
        {[], [], Seq},
        Hosts2
    ),

    Result =
        case Addresses of
            [] ->
                Errors;
            _ ->
                [
                    spawn(fun() ->
                        gen_icmp:send(Socket, Addr, gen_icmp:echo(Family, Id, S, Data))
                    end)
                 || {ok, _Host, Addr, S} <- Addresses
                ],
                {Timeouts, Replies} = ping_reply(Addresses, #ping_opt{
                    s = Socket,
                    id = Id,
                    timeout = Timeout,
                    timestamp = Timestamp
                }),
                Errors ++ Timeouts ++ Replies
        end,

    ok = setopts(Socket, [{active, false}]),
    flush_events(Socket),
    Result.

%%-------------------------------------------------------------------------
%%% Callbacks
%%-------------------------------------------------------------------------
%% @private
start_link(RawOpts, SockOpts) ->
    Pid = self(),
    gen_server:start_link(?MODULE, [Pid, RawOpts, SockOpts], []).

%% @private
start(RawOpts, SockOpts) ->
    Pid = self(),
    case gen_server:start(?MODULE, [Pid, RawOpts, SockOpts], []) of
        {ok, Socket} -> {ok, Socket};
        {error, Error} -> Error
    end.

%% @private
init([Pid, RawOpts, SockOpts]) ->
    process_flag(trap_exit, true),

    {Protocol, Family} =
        case proplists:get_value(inet6, RawOpts, false) of
            false -> {icmp, inet};
            true -> {'ipv6-icmp', inet6}
        end,

    Result =
        case procket:socket(Family, raw, Protocol) of
            {error, eperm} ->
                procket:open(0, RawOpts ++ [{protocol, Protocol}, {type, raw}, {family, Family}]);
            N ->
                N
        end,

    init_1(Pid, Family, RawOpts, SockOpts, Result).

init_1(Pid, Family, RawOpts, SockOpts0, {ok, FD}) ->
    TTL = proplists:get_value(ttl, RawOpts),

    _ = case TTL of
        undefined -> ok;
        _ -> set_ttl(FD, Family, TTL)
    end,

    SockOpts =
        case proplists:is_defined(active, SockOpts0) of
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

%% @private
handle_call(close, {Pid, _}, #state{pid = Pid, s = Socket} = State) ->
    {stop, normal, gen_udp:close(Socket), State};
handle_call({send, IP, Packet}, _From, #state{s = Socket} = State) ->
    {reply, gen_udp:send(Socket, IP, 0, Packet), State};
handle_call({recv, Length, Timeout}, {Pid, _}, #state{pid = Pid, s = Socket} = State) ->
    Reply =
        case gen_udp:recv(Socket, Length, Timeout) of
            {ok, {Address, _Port, Packet}} -> {ok, {Address, Packet}};
            N -> N
        end,
    {reply, Reply, State};
handle_call({controlling_process, Pid}, {Owner, _}, #state{pid = Owner} = State) ->
    {reply, ok, State#state{pid = Pid}};
handle_call({setopts, Options}, {Pid, _}, #state{pid = Pid, s = Socket} = State) ->
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

%% @private
handle_cast(Msg, State) ->
    error_logger:info_report([{cast, Msg}, {state, State}]),
    {noreply, State}.

%% @private
% IPv4 ICMP
handle_info(
    {udp, Socket, {_, _, _, _} = Saddr, 0,
        <<4:4, HL:4, _ToS:8, _Len:16, _Id:16, 0:1, _DF:1, _MF:1, _Off:13, TTL:8, ?IPPROTO_ICMP:8,
            _Sum:16, _SA1:8, _SA2:8, _SA3:8, _SA4:8, _DA1:8, _DA2:8, _DA3:8, _DA4:8, Data/binary>>},
    #state{pid = Pid, s = Socket} = State
) ->
    N = (HL - 5) * 4,
    Opt =
        if
            N > 0 -> N;
            true -> 0
        end,

    <<_:Opt/bits, Payload/bits>> = Data,
    Pid ! {icmp, self(), Saddr, TTL, Payload},
    {noreply, State};
% IPv6 ICMP
handle_info(
    {udp, Socket, {_, _, _, _, _, _, _, _} = Saddr, 0, Data},
    #state{pid = Pid, fd = FD, s = Socket} = State
) ->
    {ok, TTL} = get_ttl(FD, inet6),
    Pid ! {icmp, self(), Saddr, TTL, Data},
    {noreply, State};
handle_info({'EXIT', _, normal}, State) ->
    {noreply, State};
handle_info(Info, State) ->
    error_logger:info_report([{info, Info}, {state, State}]),
    {noreply, State}.

%% @private
terminate(_Reason, #state{fd = Socket}) ->
    procket:close(Socket),
    ok.

%% @private
code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%%-------------------------------------------------------------------------
%%% Utility Functions
%%-------------------------------------------------------------------------

%% @doc Create an ICMP packet
%%
%% Convenience function for creating arbitrary ICMP packets. This
%% function will calculate the ICMP checksum and insert it into the
%% packet.
%%
%% == Examples ==
%%
%% ```
%% 1> rr("_build/default/lib/pkt/include/pkt_icmp.hrl").
%% [icmp]
%% 2> gen_icmp:packet(#icmp{}, <<"abc">>).
%% <<8,0,51,157,0,0,0,0,97,98,99>>
%% '''
-spec packet(#icmp{} | #icmp6_pseudohdr{}, binary()) -> binary().
packet(#icmp{} = Header, Payload) when is_binary(Payload) ->
    Sum = pkt:makesum(
        list_to_binary([
            pkt:icmp(Header),
            Payload
        ])
    ),
    list_to_binary([
        pkt:icmp(Header#icmp{checksum = Sum}),
        Payload
    ]);
packet(
    #icmp6_pseudohdr{
        saddr = {SA1, SA2, SA3, SA4, SA5, SA6, SA7, SA8},
        daddr = {DA1, DA2, DA3, DA4, DA5, DA6, DA7, DA8},
        len = Len,
        next = Next,
        h = Header
    },
    Payload
) when is_binary(Payload) ->
    Sum = pkt:makesum(
        list_to_binary([
            <<SA1, SA2, SA3, SA4, SA5, SA6, SA7, SA8, DA1, DA2, DA3, DA4, DA5, DA6, DA7, DA8,
                Len:32, 0:24, Next:8>>,
            pkt:icmp6(Header),
            Payload
        ])
    ),
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
    Saddr = proplists:get_value(saddr, Header, {0, 0, 0, 0, 0, 0, 0, 0}),
    Daddr = proplists:get_value(daddr, Header, {0, 0, 0, 0, 0, 0, 0, 0}),
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

%% @doc Generate ICMP ECHO_REQUEST payload
%%
%% Creates an ICMP echo packet with an 8 byte timestamp and a
%% payload consisting of ASCII 32 to 79.
%%
%% == Examples ==
%%
%% ```
%% 1> gen_icmp:echo(inet, 0, 0).
%% <<8,0,166,49,0,0,0,0,255,253,243,182,71,2,233,209,32,33,
%%   34,35,36,37,38,39,40,41,42,43,44,...>>
%% '''
-spec echo(inet | inet6, id(), sequence()) -> binary().
echo(Family, Id, Seq) ->
    % Pad packet to 64 bytes
    echo(Family, Id, Seq, payload(echo)).

%% @doc Generate ICMP ECHO_REQUEST with user specified payload
%%
%% Creates an ICMP echo packet with the results of
%% erlang:monotonic_time(micro_seconds) used as the timestamp and a user
%% specified payload (padded to 64 bytes).
%%
%% == Examples ==
%%
%% ```
%% 1> gen_icmp:echo(inet, 0, 0, <<"ping", 0:(60*8)>>).
%% <<8,0,25,47,0,0,0,0,112,105,110,103,0,0,0,0,0,0,0,0,0,0,0,
%%   0,0,0,0,0,0,...>>
%% '''
-spec echo(inet | inet6, id(), sequence(), <<_:64>>) -> binary().
echo(Family, Id, Seq, Payload) when
    is_integer(Id),
    Id >= 0,
    Id < 16#FFFF,
    is_integer(Seq),
    Seq >= 0,
    Seq < 16#FFFF,
    is_binary(Payload)
->
    Echo =
        case Family of
            inet -> echo;
            inet6 -> echo_request
        end,

    packet(
        Family,
        [
            {type, Echo},
            {id, Id},
            {sequence, Seq}
        ],
        Payload
    ).

% Default ICMP echo payload
payload(echo) ->
    USec = gettime(),
    <<USec:8/signed-integer-unit:8, (list_to_binary(lists:seq($\s, $O)))/binary>>.

%% @doc Set the TTL on a file descriptor
%%
%% == Examples ==
%%
%% ```
%% 1> gen_icmp:set_ttl(gen_icmp:getfd(S), gen_icmp:family(S), 1).
%% ok
%% 2> gen_icmp:get_ttl(gen_icmp:getfd(S), gen_icmp:family(S)).
%% {ok,1}
%% '''
-spec set_ttl(fd(), inet | inet6, int32_t()) -> ok | {error, inet:posix()}.
set_ttl(FD, inet, TTL) ->
    procket:setsockopt(FD, ?IPPROTO_IP, ip_ttl(), <<TTL:32/native>>);
set_ttl(FD, inet6, TTL) ->
    procket:setsockopt(FD, ?IPPROTO_IPV6, ipv6_unicast_hops(), <<TTL:32/native>>).

%% @doc Get the TTL for a file descriptor
%%
%% == Examples ==
%%
%% ```
%% 1> gen_icmp:get_ttl(gen_icmp:getfd(S), gen_icmp:family(S)).
%% {ok,64}
%% '''
-spec get_ttl(fd(), inet | inet6) -> {ok, int32_t()} | {error, inet:posix()}.
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

%% @doc Resolve a host list.
%%
%% == Examples ==
%%
%% ```
%% 1> gen_icmp:addr_list(inet, ["8.8.8.8", "google.com", "cloudflare.com", {8,8,8,8}, "8.8.8.8"], false).
%% [{ok,"8.8.8.8",{8,8,8,8}},
%%  {ok,"google.com",{172,217,165,14}},
%%  {ok,"cloudflare.com",{104,16,133,229}},
%%  {ok,{8,8,8,8},{8,8,8,8}},
%%  {ok,"8.8.8.8",{8,8,8,8}}]
%%
%% 2> [{ok,"8.8.8.8",{8,8,8,8}},
%%  {ok,"google.com",{172,217,165,14}},
%%  {ok,"cloudflare.com",{104,16,132,229}},
%%  {ok,"cloudflare.com",{104,16,133,229}},
%%  {ok,{8,8,8,8},{8,8,8,8}},
%%  {ok,"8.8.8.8",{8,8,8,8}}]
%% '''
-spec addr_list(inet | inet6, [inet:socket_address() | inet:hostname()], boolean()) ->
    [
        {ok, inet:hostname(), inet:socket_address()}
        | {error, inet:posix(), inet:hostname(), undefined}
    ].
addr_list(Family, Hosts, Multi) ->
    lists:flatmap(
        fun(Host) ->
            case parse(Family, Host) of
                {ok, IPs} when Multi == true ->
                    [{ok, Host, IP} || IP <- IPs];
                {ok, [IP | _]} ->
                    [{ok, Host, IP}];
                {error, Error} ->
                    [{error, Error, Host, undefined}]
            end
        end,
        Hosts
    ).

%% @doc Parse or resolve an IPv4 host identifier
%%
%% == Examples ==
%%
%% ```
%% 1> gen_icmp:parse("8.8.8.8").
%% {ok,[{8,8,8,8}]}
%%
%% 2> gen_icmp:parse({8,8,8,8}).
%% {ok,[{8,8,8,8}]}
%%
%% 3> gen_icmp:parse("2001:4860:4860::8888").
%% {ok,[{8193,18528,18528,0,0,0,0,34952}]}
%%
%% 4> gen_icmp:parse("cloudflare.com").
%% {ok,[{104,16,132,229},{104,16,133,229}]}
%%
%% 5> gen_icmp:parse("foo").
%% {error,nxdomain}
%% '''
-spec parse([inet:socket_address() | inet:hostname()]) ->
    {ok, [inet:socket_address()]} | {error, inet:posix()}.
parse(Addr) ->
    parse(inet, Addr).

%% @doc Parse or resolve a host identifier
%%
%% == Examples ==
%%
%% ```
%% 1> gen_icmp:parse(inet, "cloudflare.com").
%% {ok,[{104,16,133,229},{104,16,132,229}]}
%%
%% 2> gen_icmp:parse(inet6, "cloudflare.com").
%% {ok,[{9734,18176,0,0,0,0,26640,34021},
%%      {9734,18176,0,0,0,0,26640,34277}]}
%% '''
-spec parse(inet | inet6, [inet:socket_address() | inet:hostname()]) ->
    {ok, [inet:socket_address()]} | {error, inet:posix()}.
parse(Family, Addr) when is_list(Addr) ->
    parse_or_resolve(Family, Addr, inet_parse:address(Addr));
parse(_Family, Addr) when is_tuple(Addr) ->
    {ok, [Addr]}.

% IPv6 ICMP filtering
%
% Linux reverses the meaning of the macros in RFC3542
icmp6_filter_setpassall() ->
    case os:type() of
        {unix, linux} ->
            <<0:256>>;
        {unix, _} ->
            <<16#ff, 16#ff, 16#ff, 16#ff, 16#ff, 16#ff, 16#ff, 16#ff, 16#ff, 16#ff, 16#ff, 16#ff,
                16#ff, 16#ff, 16#ff, 16#ff, 16#ff, 16#ff, 16#ff, 16#ff, 16#ff, 16#ff, 16#ff, 16#ff,
                16#ff, 16#ff, 16#ff, 16#ff, 16#ff, 16#ff, 16#ff, 16#ff>>
    end.

icmp6_filter_setblockall() ->
    case os:type() of
        {unix, linux} ->
            <<16#ff, 16#ff, 16#ff, 16#ff, 16#ff, 16#ff, 16#ff, 16#ff, 16#ff, 16#ff, 16#ff, 16#ff,
                16#ff, 16#ff, 16#ff, 16#ff, 16#ff, 16#ff, 16#ff, 16#ff, 16#ff, 16#ff, 16#ff, 16#ff,
                16#ff, 16#ff, 16#ff, 16#ff, 16#ff, 16#ff, 16#ff, 16#ff>>;
        {unix, _} ->
            <<0:256>>
    end.

%% @doc Allowed types for an ICMPv6 socket
%%
%% Generate a ICMPv6 filter that can be set on a socket using
%% filter/2.
%%
%% == Examples ==
%%
%% To generate a filter that allowed only ICMP6_ECHO_REPLY messages:
%%
%% ```
%% {ok, Socket} = gen_icmp:open([inet6]),
%% Filter = gen_icmp:icmp6_filter_setpass(echo_reply,
%% gen_icmp:icmp6_filter_setblockall()),
%% ok = gen_icmp:filter(Socket, Filter).
%% '''

%#define ICMP6_FILTER_SETPASS(type, filterp) \
%            (((filterp)->icmp6_filt[(type) >> 5]) |= (1 << ((type) & 31)))
icmp6_filter_setpass(Type0, <<_:256>> = Filter) ->
    Type = icmp6_message:type_to_uint8(Type0),
    Offset = Type bsr 5,
    Value = 1 bsl (Type band 31),
    Fun =
        case os:type() of
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
    Fun =
        case os:type() of
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
    case os:type() of
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
    case os:type() of
        {unix, linux} -> El band Value =/= 0;
        {unix, _} -> El band Value =:= 0
    end.

%%-------------------------------------------------------------------------
%%% Internal Functions
%%-------------------------------------------------------------------------

parse_or_resolve(_Family, _Addr, {ok, IP}) ->
    {ok, [IP]};
parse_or_resolve(Family, Addr, {error, einval}) ->
    case inet:gethostbyname(Addr, Family) of
        {ok, #hostent{h_addr_list = IPs}} ->
            {ok, IPs};
        Error ->
            Error
    end.

ping_reply(Hosts, #ping_opt{s = Socket, timeout = Timeout} = Opt) ->
    Pid = self(),
    TRef =
        case Timeout of
            infinity ->
                infinity;
            _ ->
                erlang:send_after(Timeout, Pid, {icmp, Socket, timeout})
        end,
    ping_loop(Hosts, [], Opt#ping_opt{tref = TRef}).

cancel_timeout(infinity) ->
    false;
cancel_timeout(TRef) ->
    erlang:cancel_timer(TRef).

ping_loop([], Acc, #ping_opt{tref = TRef}) ->
    _ = cancel_timeout(TRef),
    {[], Acc};
ping_loop(
    Hosts,
    Acc,
    #ping_opt{
        tref = TRef,
        s = Socket,
        id = Id,
        timestamp = Timestamp
    } = Opt
) ->
    receive
        % IPv4 ICMP Echo Reply
        {icmp, Socket, {_, _, _, _} = Reply, TTL,
            <<?ICMP_ECHOREPLY:8, 0:8, _Checksum:16, Id:16, Seq:16, Data/binary>>} ->
            {Elapsed, Payload} =
                case Timestamp of
                    true ->
                        <<USec:8/signed-integer-unit:8, Data1/binary>> = Data,
                        {timediff(USec) div 1000, Data1};
                    false ->
                        {0, Data}
                end,
            {Hosts2, Result} =
                case lists:keytake(Seq, 4, Hosts) of
                    {value, {ok, Addr, Address, Seq}, NHosts} ->
                        {NHosts, [
                            {ok, Addr, Address, Reply, {Id, Seq, TTL, Elapsed}, Payload} | Acc
                        ]};
                    false ->
                        {Hosts, Acc}
                end,
            ping_loop(Hosts2, Result, Opt);
        % IPv4 ICMP Error
        {icmp, Socket, {_, _, _, _} = Reply, TTL,
            <<Type:8, Code:8, _Checksum1:16, _Unused:32, 4:4, 5:4, _ToS:8, _Len:16, _Id:16, 0:1,
                _DF:1, _MF:1, _Off:13, _TTL:8, ?IPPROTO_ICMP:8, _Sum:16, _SA1:8, _SA2:8, _SA3:8,
                _SA4:8, DA1:8, DA2:8, DA3:8, DA4:8, ?ICMP_ECHO:8, 0:8, _Checksum2:16, Id:16, Seq:16,
                _/binary>> = Data} ->
            <<_ICMPHeader:8/bytes, Payload/binary>> = Data,
            DA = {DA1, DA2, DA3, DA4},
            {Hosts2, Result} =
                case lists:keytake(Seq, 4, Hosts) of
                    {value, {ok, Addr, DA, Seq}, NHosts} ->
                        {NHosts, [
                            {error, icmp_message:code({Type, Code}), Addr, DA, Reply,
                                {Id, Seq, TTL, undefined}, Payload}
                            | Acc
                        ]};
                    false ->
                        {Hosts, Acc}
                end,
            ping_loop(Hosts2, Result, Opt);
        % IPv6 ICMP Echo Reply
        {icmp, Socket, {_, _, _, _, _, _, _, _} = Reply, TTL,
            <<?ICMP6_ECHO_REPLY:8, 0:8, _Checksum:16, Id:16, Seq:16, Data/binary>>} ->
            {Elapsed, Payload} =
                case Timestamp of
                    true ->
                        <<USec:8/signed-integer-unit:8, Data1/binary>> = Data,
                        {timediff(USec) div 1000, Data1};
                    false ->
                        {0, Data}
                end,
            {Hosts2, Result} =
                case lists:keytake(Seq, 4, Hosts) of
                    {value, {ok, Addr, Address, Seq}, NHosts} ->
                        {NHosts, [
                            {ok, Addr, Address, Reply, {Id, Seq, TTL, Elapsed}, Payload} | Acc
                        ]};
                    false ->
                        {Hosts, Acc}
                end,
            ping_loop(Hosts2, Result, Opt);
        % IPv6 ICMP Error
        {icmp, Socket, {_, _, _, _, _, _, _, _} = Reply, TTL,
            <<Type:8, Code:8, _Checksum1:16, _Unused:32, 6:4, _Class:8, _Flow:20, _Len:16,
                ?IPPROTO_ICMPV6:8, _Hop:8, _SA1:16, _SA2:16, _SA3:16, _SA4:16, _SA5:16, _SA6:16,
                _SA7:16, _SA8:16, DA1:16, DA2:16, DA3:16, DA4:16, DA5:16, DA6:16, DA7:16, DA8:16,
                ?ICMP6_ECHO_REQUEST:8, 0:8, _Checksum2:16, Id:16, Seq:16, _/binary>> = Data} ->
            <<_ICMPHeader:8/bytes, Payload/binary>> = Data,
            DA = {DA1, DA2, DA3, DA4, DA5, DA6, DA7, DA8},
            {value, {ok, Addr, DA, Seq}, Hosts2} = lists:keytake(Seq, 4, Hosts),
            {Hosts2, Result} =
                case lists:keytake(Seq, 4, Hosts) of
                    {value, {ok, Addr, DA, Seq}, NHosts} ->
                        {NHosts, [
                            {error, icmp_message:code({Type, Code}), Addr, DA, Reply,
                                {Id, Seq, TTL, undefined}, Payload}
                            | Acc
                        ]};
                    false ->
                        {Hosts, Acc}
                end,
            ping_loop(Hosts2, Result, Opt);
        % IPv4/IPv6 timeout on socket
        {icmp, Socket, timeout} ->
            _ = cancel_timeout(TRef),
            Timeouts = [{error, timeout, Addr, IP} || {ok, Addr, IP, _Seq} <- Hosts],
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

icmp6_filter() ->
    case os:type() of
        {unix, linux} ->
            1;
        {unix, _} ->
            18
    end.

% Offset starts at 0
array_set(Offset, Fun, Bin) ->
    Array = array:from_list([N || <<N:4/native-unsigned-integer-unit:8>> <= Bin]),
    Value = Fun(array:get(Offset, Array)),
    <<
        <<N:4/native-unsigned-integer-unit:8>>
     || N <- array:to_list(array:set(Offset, Value, Array))
    >>.

array_get(Offset, Bin) ->
    Array = array:from_list([N || <<N:4/native-unsigned-integer-unit:8>> <= Bin]),
    array:get(Offset, Array).

flush_events(Socket) ->
    receive
        {icmp, Socket, _Addr, _TTL, _Data} ->
            flush_events(Socket)
    after 0 -> ok
    end.

gettime() ->
    try erlang:monotonic_time(micro_seconds) of
        N ->
            N
    catch
        error:undef ->
            timestamp_to_microseconds(os:timestamp())
    end.

timediff(T) ->
    timediff(gettime(), T).

timediff(T1, T2) ->
    T1 - T2.

timestamp_to_microseconds({MegaSecs, Secs, MicroSecs}) ->
    (MegaSecs * 1000000 + Secs) * 1000000 + MicroSecs.
