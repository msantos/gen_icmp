%% Copyright (c) 2012-2023, Michael Santos <michael.santos@gmail.com>
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
-module(icmp6_message).
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
type(?ICMP6_DST_UNREACH) -> dst_unreach;
type(?ICMP6_PACKET_TOO_BIG) -> packet_too_big;
type(?ICMP6_TIME_EXCEEDED) -> time_exceeded;
type(?ICMP6_PARAM_PROB) -> param_prob;
type(?ICMP6_ECHO_REQUEST) -> echo_request;
type(?ICMP6_ECHO_REPLY) -> echo_reply;
type(dst_unreach) -> ?ICMP6_DST_UNREACH;
type(packet_too_big) -> ?ICMP6_PACKET_TOO_BIG;
type(time_exceeded) -> ?ICMP6_TIME_EXCEEDED;
type(param_prob) -> ?ICMP6_PARAM_PROB;
type(echo_request) -> ?ICMP6_ECHO_REQUEST;
type(echo_reply) -> ?ICMP6_ECHO_REPLY.

%%
%% ICMP control message: codes
%%

% destination unreachable
code(dst_unreach_noroute) ->
    ?ICMP6_DST_UNREACH_NOROUTE;
code(dst_unreach_admin) ->
    ?ICMP6_DST_UNREACH_ADMIN;
code(dst_unreach_beyondscope) ->
    ?ICMP6_DST_UNREACH_BEYONDSCOPE;
code(dst_unreach_addr) ->
    ?ICMP6_DST_UNREACH_ADDR;
code(dst_unreach_noport) ->
    ?ICMP6_DST_UNREACH_NOPORT;
% time exceeded
code(time_exceed_transit) ->
    ?ICMP6_TIME_EXCEED_TRANSIT;
code(time_exceed_reassembly) ->
    ?ICMP6_TIME_EXCEED_REASSEMBLY;
% parameter problem
code(paramprob_header) ->
    ?ICMP6_PARAMPROB_HEADER;
code(paramprob_nextheader) ->
    ?ICMP6_PARAMPROB_NEXTHEADER;
code(paramprob_option) ->
    ?ICMP6_PARAMPROB_OPTION;
% destination unreachable
code({?ICMP6_DST_UNREACH, ?ICMP6_DST_UNREACH_NOROUTE}) ->
    dst_unreach_noroute;
code({?ICMP6_DST_UNREACH, ?ICMP6_DST_UNREACH_ADMIN}) ->
    dst_unreach_admin;
code({?ICMP6_DST_UNREACH, ?ICMP6_DST_UNREACH_BEYONDSCOPE}) ->
    dst_unreach_beyondscope;
code({?ICMP6_DST_UNREACH, ?ICMP6_DST_UNREACH_ADDR}) ->
    dst_unreach_addr;
code({?ICMP6_DST_UNREACH, ?ICMP6_DST_UNREACH_NOPORT}) ->
    dst_unreach_noport;
% time exceeded
code({?ICMP6_TIME_EXCEEDED, ?ICMP6_TIME_EXCEED_TRANSIT}) ->
    time_exceed_transit;
code({?ICMP6_TIME_EXCEEDED, ?ICMP6_TIME_EXCEED_REASSEMBLY}) ->
    time_exceed_reassembly;
% parameter problem
code({?ICMP6_PARAM_PROB, ?ICMP6_PARAMPROB_HEADER}) ->
    paramprob_header;
code({?ICMP6_PARAM_PROB, ?ICMP6_PARAMPROB_NEXTHEADER}) ->
    paramprob_nextheader;
code({?ICMP6_PARAM_PROB, ?ICMP6_PARAMPROB_OPTION}) ->
    paramprob_option;
% echo
code({?ICMP6_ECHO_REQUEST, 0}) ->
    echo_request;
code({?ICMP6_ECHO_REPLY, 0}) ->
    echo_reply;
code({Type, Code}) when is_integer(Type), is_integer(Code) ->
    {unknown, Type, Code}.
