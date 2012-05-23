%% Copyright (c) 2012, Michael Santos <michael.santos@gmail.com>
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
-module(icmp_message).
-include_lib("pkt/include/pkt.hrl").

-export([
        type_to_uint8/1,
        code_to_uint8/1,

        type/1,
        code/1
    ]).


type_to_uint8(Type) when is_integer(Type) -> Type;
type_to_uint8(Type) when is_atom(Type) -> type(Type).
  
code_to_uint8(Code) when is_integer(Code) -> Code;
code_to_uint8(Code) when is_atom(Code) -> code(Code).


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

code({Type, Code}) when is_integer(Type), is_integer(Code) ->
    {unknown, Type, Code}.
