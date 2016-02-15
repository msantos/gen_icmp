
gen\_icmp aspires to be a simple interface for using ICMP and ICMPv6
sockets in Erlang, just like gen\_tcp and gen\_udp do for their protocol
types; incidentally messing up Google searches for whomever someday
writes a proper gen\_icmp module.

gen\_icmp uses procket to get a raw socket and abuses gen\_udp for the
socket handling. gen\_icmp should work on Linux and BSDs.

The interfaces, return values and code may still change before the final
version. If you just need a simple example of sending a ping, also see:

<https://github.com/msantos/procket/blob/master/src/icmp.erl>


## EXPORTS

    open() -> {ok, Socket}
    open(SocketOptions) -> {ok, Socket}
    open(RawOptions, SocketOptions) -> {ok, Socket}

        Types   Socket = pid()
                RawOptions = [ RawOption ]
                RawOption = options()
                SocketOptions = SocketOpt
                SocketOpt = [ {active, true} | {active, once} |
                    {active, false} | inet | inet6 ]

        By default, the ICMP socket is opened in {active,false} mode. No
        packets will be received by the socket. setopts/2 can be used
        to place the socket in {active,true} mode.

        See the procket README for the raw socket options and for
        instructions on setting up the setuid helper.

        gen_icmp first attempts to natively open the socket and falls
        back to forking the setuid helper program if beam does not have
        the appropriate privileges.  Privileges to open a raw socket can
        be given by, for example, running as root or, on Linux, granting
        the CAP_NET_RAW capability to beam:

            setcap cap_net_raw=ep /usr/local/lib/erlang/erts-5.8.3/bin/beam.smp

        Only the owning process will receive ICMP packets (see
        controlling_process/2 to change the owner). The process owning the
        raw socket will receive all ICMP packets sent to the host.

        Messages sent to the controlling process are:

        {icmp, Socket, Address, TTL, Packet}

        Where:

            * Socket is the pid of the gen_icmp process

            * Address is a tuple representing the IPv4 or IPv6 source address

            * TTL is the IP TTL
                * IPv4: TTL take from the IP header
                * IPv6: the socket's hop limit returned from
                  getsockopt(IPV6_UNICAST_HOPS) (this is not the packet's
                  TTL, it is the socket's max TTL)

            * Packet is the complete ICMP packet including the ICMP headers

    close(Socket) -> ok | {error, Reason}

        Types   Socket = pid()
                Reason = posix()

        Close the ICMP socket.

    send(Socket, Address, Packet) -> ok | {error, Reason}

        Types   Socket = pid()
                Address = tuple()
                Packet = binary()
                Reason = not_owner | posix()

        Like the gen_udp and gen_tcp modules, any process can send ICMP
        packets but only the owner will receive the responses.

    recv(Socket, Length) -> {ok, {Address, Packet}} | {error, Reason}
    recv(Socket, Length, Timeout) -> {ok, {Address, Packet}} | {error, Reason}

        Types   Socket = socket()
                Length = int()
                Address = ip_address()
                Packet = [char()] | binary()
                Timeout = int() | infinity
                Reason = not_owner | posix()

        This function receives a packet from a socket in passive mode.

        The optional Timeout parameter specifies a timeout in
        milliseconds. The default value is infinity .

    controlling_process(Socket, Pid) -> ok

        Types   Socket = pid()
                Pid = pid()

        Change the process owning the socket. Allows another process to
        receive the ICMP responses.

    setopts(Socket, Options) ->

        Types   Socket = pid()
                Options = list()

        For options, see the inet man page. Simply calls inet:setopts/2
        on the gen_udp socket.

        setopts/2 can be used to toggle the socket between passive and
        active mode:

            {ok, Socket} = gen_icmp:open(), % socket is {active,false}
            ok = gen_icmp:setopts(Socket, [{active, true}]),
            % do stuff with the socket
            ok = gen_icmp:setopts(Socket, [{active, false}]).

    ping(Host) -> Responses
    ping(Host, Options) -> Responses
    ping(Socket, Hosts, Options) -> Responses

        Types   Socket = pid()
                Host = Address | Hostname | Hosts
                Address = ReplyAddr = tuple()
                Hostname = string()
                Hosts = [ tuple() | string() ]
                Options = [ Option ]
                Option = {id, Id} | {sequence, Sequence} | {timeout, Timeout} | {data, Data} |
                    {timestamp, boolean()} | {ttl, TTL} | {filter, Filter} | inet | inet6
                Id = uint16()
                Sequence = uint16()
                Timeout = int()
                TTL = uint8()
                Data = binary()
                Filter = binary()
                Responses = [ Response ]
                Response = {ok, Host, Address, ReplyAddr, Details, Payload}
                    | {error, ICMPError, Host, Address, ReplyAddr, Details, Payload}
                    | {error, Error, Host, Address}
                Details = {Id, Sequence, TTL, Elapsed}
                Elapsed = int() | undefined
                Payload = binary()
                ICMPError = unreach_host | timxceed_intrans
                Error = timeout | inet:posix()

        ping/1 is a convenience function to send a single ping
        packet. The argument to ping/1 can be either a hostname or a
        list of hostnames.

        To prevent the process mailbox from being flooded with ICMP
        messages, ping/3 will put the socket into {active,false} mode
        after completing.

        The ping/3 function blocks until either an ICMP ECHO REPLY is
        received from all hosts or Timeout is reached.

        Id and sequence are used to differentiate ping responses. Usually,
        the sequence is incremented for each ping in one run.

        A list of responses is returned. If the ping was successful,
        the elapsed time in milliseconds is included (calculated by
        subtracting the current time from the time we sent in the ICMP
        ECHO packet and returned to us in the ICMP ECHOREPLY payload)
        where:

            Host: the provided hostname

            Address: the resolved IPv4 or IPv6 network address represented
            as a 4 or 8-tuple used in the ICMP echo request

            ReplyAddr: the IPv4 or IPv6 network address originating the
            ICMP echo reply

        The timeout is set for all ICMP packets and is set after all
        packets have been sent out.

        ping/1 and ping/2 open and close an ICMP socket for the user. For
        best performance, ping/3 should be used instead, with the socket
        being maintained between runs.

        By default only one address per hostname is pinged. To
        enable pinging all addresses per hostname pass {multi, true}
        to options.

        A ping payload contains a 12 byte timestamp generated using
        erlang:now/0. When creating a custom payload, the first 12 bytes of
        the ICMP echo reply payload will be used for calculating the elapsed
        time. To disable this behaviour, use the option {timestamp,false}
        (the elapsed time in the return value will be set to 0).

        The timeout defaults to 5 seconds.

        ICMPv6 sockets can restrict which ICMPv6 types are received by the
        socket using the filter option.  The filter argument is a binary
        generated using the icmp6_filter functions described below.

        The default filter allows: ICMP6_ECHO_REPLY, ICMP6_DST_UNREACH,
        ICMP6_PACKET_TOO_BIG, ICMP6_TIME_EXCEEDED and ICMP6_PARAM_PROB.
        Note: ping/3 does not restore the original filter on the socket.

    echo(Id, Sequence) -> Packet

        Types   Id = uint16()
                Sequence = uint16()
                Packet = binary()

        Creates an ICMP echo packet with the results of erlang:now() used
        as the timestamp and a payload consisting of ASCII 32 to 75.

    echo(Id, Sequence, Payload) -> Packet

        Types   Id = uint16()
                Sequence = uint16()
                Payload = binary()
                Packet = binary()

        Creates an ICMP echo packet with the results of erlang:now() used
        as the timestamp and a user specified payload (which should pad the
        packet to 64 bytes).


    packet(Header, Payload) -> Packet

        Types   Header = [ #icmp{} | Options ]
                Options = [ Opts ]
                Opts = [{type, Type} | {code, Code} | {id, Id} | {sequence, Sequence} |
                            {gateway, Gateway} | {mtu, MTU} | {pointer, Pointer} |
                            {ts_orig, TS_orig} | {ts_recv, TS_recv} | {ts_tx, TS_tx} ]
                Type = uint8() | ICMP_type
                Code = uint8() | ICMP_code
                ICMP_type = echoreply | dest_unreach | source_quench | redirect | echo |
                    time_exceeded | parameterprob | timestamp | timestampreply | info_request |
                    info_reply | address | addressreply
                ICMP_code = unreach_net | unreach_host | unreach_protocol | unreach_port |
                    unreach_needfrag | unreach_srcfail | redirect_net | redirect_host |
                    redirect_tosnet | redirect_toshost | timxceed_intrans | timxceed_reass
                Id = uint16()
                Sequence = uint16()
                Payload = binary()
                Packet = binary()

        Convenience function for creating arbitrary ICMP packets. This
        function will calculate the ICMP checksum and insert it into the
        packet.

    filter(Socket) -> {ok, Filter} | unsupported
    filter(Socket, Filter) -> ok | unsupported

        Types   Socket = pid()
                Filter = binary()

        Sets or retrieves an ICMPv6 filter on a socket. For ICMPv4
        sockets, the atom 'unsupported' is returned.

        Filters can be generated by using the icmp6_filter functions.

    icmp6_filter_setblockall() -> binary()
    icmp6_filter_setpassall() -> binary()
    icmp6_filter_setpass(Type, Filter) -> binary()
    icmp6_filter_setblock(Type, Filter) -> binary()
    icmp6_filter_willpass(Type, Filter) -> true | false
    icmp6_filter_willblock(Type, Filter) -> true | false

        Types   Type = icmp_type()
                Filter = binary()

        Generate a ICMPv6 filter that can be set on a socket using
        filter/2.

        For example, to generate a filter that allowed only
        ICMP6_ECHO_REPLY messages:

            {ok, Socket} = gen_icmp:open([inet6]),
            Filter = gen_icmp:icmp6_filter_setpass(echo_reply,
                        gen_icmp:icmp6_filter_setblockall()),
            ok = gen_icmp:filter(Socket, Filter).

### Traceroute

tracert is an Erlang traceroute implementation built using gen_icmp.

    host(Host) -> Path
    host(Host, Options) -> Path
    host(Socket, Host, Options) -> Path

        Types   Socket = pid()
                Host = Address | Hostname
                Address = tuple()
                Hostname = string()
                Options = [ Option ]
                Option = {protocol, Protocol}
                    | {max_hops, uint()}
                    | {timeout, uint()}
                    | {setuid, bool()}
                    | {saddr, Address}
                    | {sport, uint16()}
                Protocol = icmp | udp
                Path = [ {Address, MicroSeconds, {Protocol, binary()}
                    | timeout ]

        Perform a traceroute to a destination. ICMP and UDP probes are
        supported. ICMP probes are the default.

        max_hops is the maximum TTL (default: 30)

        Set the time in milliseconds to wait for a response using the
        timeout option (default: 1000 ms).  WARNING: if the response
        arrives after the timeout, tracert will insert spurious entries
        into the path.

        tracert will not spawn the setuid helper if the {setuid, false}
        option is used. In this case, beam must either be running as
        root or have the cap_net_raw privileges under Linux.

        The {sport, Port} option sets the initial source port for UDP
        probes. The port will be incremented by 1 for each subsequent
        probe (default: random high port).  For ICMP probes, the ICMP
        ID field will be set to this value.

        The return value is an ordered list of tuples:

            Adddress: the source address responding to the probe

            MicroSeconds: time elapsed between the probe and receiving
            the response

            Protocol: icmp or udp

            Protocol data: a binary representing the received packet
            contents

    path(Path) -> Reasons

        Types   Path = [ {Address, MicroSeconds, {Protocol, binary()} ]
                Reasons = [ {Address, MicroSeconds, Reason} ]
                Reason = ICMP | UDP | timeout
                ICMP = timxceed_intrans | echo_reply | ...
                UDP = unreach_port | ...

        Convert the list of binaries returned by host/1,2,3 to atoms
        representing the ICMP reponse codes and UDP errors.


## COMPILING

    $ make

Also see the README for procket for additional setup (the procket
executable needs superuser privileges).


## EXAMPLE

### Simple ping interface

    1> gen_icmp:ping("www.google.com").
    [{ok,"www.google.com",
         {173,194,64,99},
         {173,194,64,99},
         18411,0,50,
         <<" !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJK">>}]

    2> gen_icmp:ping(["www.google.com", {192,168,213,4}, "193.180.168.20", {192,0,32,10}]).
    [{error,timeout,"193.180.168.20",{193,180,168,20}},
     {error,unreach_host,
            {192,168,213,4},
            {192,168,213,4},
            {192,168,213,54},
            {18411,2,undefined},
            <<69,0,0,84,0,0,64,0,64,1,15,29,192,168,213,54,192,168,
              213,4,...>>},
     {ok,{192,0,32,10},
         {192,0,32,10},
         {192,0,32,10},
         {18411,1,103},
         <<" !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJK">>},
     {ok,"www.google.com",
         {173,194,77,99},
         {173,194,77,99},
         {18411,0,50},
         <<" !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJK">>}]

### IPv6

    1> gen_icmp:ping("google.com", [inet6]).
    [{ok,"google.com",
         {9735,63664,16395,2054,0,0,0,4098},
         {9735,63664,16395,2054,0,0,0,4098},
         {18411,0,64,62},
         <<" !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJK">>}]

    2> tracert:host("google.com", [inet6]).


### Re-using the ICMP ping socket

Keeping the ICMP socket around between runs is more efficient:

    {ok, Socket} = gen_icmp:open(),
    P1 = gen_icmp:ping(Socket, [{10,1,1,1}, "www.google.com"], []),
    P2 = gen_icmp:ping(Socket, [{10,2,2,2}, "www.yahoo.com"], []),
    gen_icmp:close(Socket).


### Working with ICMP sockets

    {ok, Socket} = gen_icmp:open().

    % By default, the ICMP socket is in passive mode
    ok = gen_icmp:setopts(Socket, [{active, true}]),

    % ICMP host unreachable, empty payload (should contain an IPv4 header
    % and the first 8 bytes of the packet data)
    Packet = gen_icmp:packet([{type, 3}, {code, 0}], <<0:160, 0:64>>).

    gen_icmp:send(Socket, {127,0,0,1}, Packet),

    % Put the socket back into passive mode
    ok = gen_icmp:setopts(Socket, [{active, false}]).


### Setting Up an ICMP Ping Tunnel

ptun is an example of using gen\_icmp to tunnel TCP over ICMP.

To compile ptun:

    make eg

Host1 (1.1.1.1) listens for TCP on port 8787 and forwards the data
over ICMP:

    erl -noshell -pa ebin deps/*/ebin -eval 'ptun:server({2,2,2,2},8787)' -s init stop

Host2 (2.2.2.2) receives ICMP echo requests and opens a TCP connection
to 127.0.0.1:22:

    erl -noshell -pa ebin deps/*/ebin -eval 'ptun:client({1,1,1,1},22)' -s init stop

To use the proxy on host1:

    ssh -p 8787 127.0.0.1

### Traceroute

* ICMP traceroute

        1> Path = tracert:host({8,8,8,8}).
        [{{216,239,46,191},
         36149,
         {icmp,<<11,0,111,150,0,0,0,0,69,128,0,84,0,0,64,...>>}},
         {{216,239,47,189},
         51459,
         {icmp,<<11,0,111,150,0,0,0,0,69,128,0,84,0,0,...>>}},
         {{8,8,8,8},
         34946,
         {icmp,<<0,0,170,0,219,104,0,0,32,33,34,35,36,...>>}}]

        2> tracert:path(Path).
        [{{216,239,46,191},62815,timxceed_intrans},
         {{216,239,47,189},44244,timxceed_intrans},
         {{8,8,8,8},34825,echoreply}]

* UDP traceroute

        1> Path = tracert:host({8,8,8,8}, [{protocol, udp}]).

* IPv6 traceroute

        1> Path = tracert:host("google.com", [inet6]).

### TODO

* tests: do not depend on list order

* handle rfc 4884 (Extended ICMP to Support Multi-Part Messages)

* handle ICMP router renumbering messages

* IPv6: handle socket ancillary data (RFC 3542)
    * retrieve the packet TTL rather than using the IPV6\_UNICAST\_HOPS
