[![Package Version](https://img.shields.io/hexpm/v/gen_icmp)](https://hex.pm/packages/gen_icmp)
[![Hex Docs](https://img.shields.io/badge/hex-docs)](https://hexdocs.pm/gen_icmp/)

gen_icmp aspires to be a simple interface for using ICMP and ICMPv6
sockets in Erlang, just like gen_tcp and gen_udp do for their protocol
types; incidentally messing up Google searches for whomever someday
writes a proper gen_icmp module.

gen_icmp uses procket to get a raw socket and abuses gen_udp for the
socket handling. gen_icmp should work on Linux and BSDs.

For a simple example of sending a ping, also see:

https://github.com/msantos/procket/blob/master/src/icmp.erl

## COMPILING

```
rebar3 do clean, compile, ct
```

Also see the README for procket for additional setup (the procket
executable needs superuser privileges).

## DOCUMENTATION

https://hexdocs.pm/gen_icmp/

## EXAMPLE

### Simple ping interface

```erlang
1> gen_icmp:ping("www.google.com").
[{ok,"www.google.com",
     {173,194,64,99},
     {173,194,64,99},
     18411,0,50,
     <<" !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNO">>}]

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
     <<" !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNO">>},
 {ok,"www.google.com",
     {173,194,77,99},
     {173,194,77,99},
     {18411,0,50},
     <<" !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNO">>}]
```

### IPv6

```erlang
1> gen_icmp:ping("google.com", [inet6]).
[{ok,"google.com",
     {9735,63664,16395,2054,0,0,0,4098},
     {9735,63664,16395,2054,0,0,0,4098},
     {18411,0,64,62},
     <<" !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNO">>}]

2> tracert:host("google.com", [inet6]).
```

### Re-using the ICMP ping socket

Keeping the ICMP socket around between runs is more efficient:

```erlang
{ok, Socket} = gen_icmp:open(),
P1 = gen_icmp:ping(Socket, [{10,1,1,1}, "www.google.com"], []),
P2 = gen_icmp:ping(Socket, [{10,2,2,2}, "www.yahoo.com"], []),
gen_icmp:close(Socket).
```

### Working with ICMP sockets

```erlang
{ok, Socket} = gen_icmp:open().

% By default, the ICMP socket is in passive mode
ok = gen_icmp:setopts(Socket, [{active, true}]),

% ICMP host unreachable, empty payload (should contain an IPv4 header
% and the first 8 bytes of the packet data)
Packet = gen_icmp:packet([{type, 3}, {code, 0}], <<0:160, 0:64>>).

gen_icmp:send(Socket, {127,0,0,1}, Packet),

% Put the socket back into passive mode
ok = gen_icmp:setopts(Socket, [{active, false}]).
```

### Setting Up an ICMP Ping Tunnel

ptun is an example of using gen\_icmp to tunnel TCP over ICMP.

To compile ptun:

```bash
make eg
```

Host1 (1.1.1.1) listens for TCP on port 8787 and forwards the data
over ICMP:

```bash
erl -noshell -pa ebin deps/*/ebin -eval 'ptun:server({2,2,2,2},8787)' -s erlang halt
```

Host2 (2.2.2.2) receives ICMP echo requests and opens a TCP connection
to 127.0.0.1:22:

```bash
erl -noshell -pa ebin deps/*/ebin -eval 'ptun:client({1,1,1,1},22)' -s erlang halt
```

To use the proxy on host1:

```bash
ssh -p 8787 127.0.0.1
```

### Traceroute

* ICMP traceroute

  ```erlang
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
  ```

* UDP traceroute

  ```erlang
  1> Path = tracert:host({8,8,8,8}, [{protocol, udp}]).
  ```

* IPv6 traceroute

  ```erlang
  1> Path = tracert:host("google.com", [inet6]).
  ```
