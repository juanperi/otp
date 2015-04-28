%%
%% %CopyrightBegin%
%% 
%% Copyright Ericsson AB 2004-2015. All Rights Reserved.
%% 
%% The contents of this file are subject to the Erlang Public License,
%% Version 1.1, (the "License"); you may not use this file except in
%% compliance with the License. You should have received a copy of the
%% Erlang Public License along with this software. If not, it can be
%% retrieved online at http://www.erlang.org/.
%% 
%% Software distributed under the License is distributed on an "AS IS"
%% basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See
%% the License for the specific language governing rights and limitations
%% under the License.
%% 
%% %CopyrightEnd%
%%
%%

-module(ssl_eqc_handshake_encode_decode).

-compile(export_all).

-proptest(eqc).
-proptest([triq,proper]).

-ifndef(EQC).
-ifndef(PROPER).
-ifndef(TRIQ).
-define(EQC,true).
%%-define(PROPER,true).
%%-define(TRIQ,true).
-endif.
-endif.
-endif.

-ifdef(EQC).
-include_lib("eqc/include/eqc.hrl").
-define(MOD_eqc,eqc).

-else.
-ifdef(PROPER).
-include_lib("proper/include/proper.hrl").
-define(MOD_eqc,proper).

-else.
-ifdef(TRIQ).
-define(MOD_eqc,triq).
-include_lib("triq/include/triq.hrl").

-endif.
-endif.
-endif.

-include_lib("ssl/src/tls_handshake.hrl").
-include_lib("ssl/src/ssl_handshake.hrl").
-include_lib("ssl/src/ssl_alert.hrl").
-include_lib("ssl/src/ssl_internal.hrl").

%%--------------------------------------------------------------------
%% Properties --------------------------------------------------------
%%--------------------------------------------------------------------

prop_ssl_decode_encode() ->
    SSLVersion = {3,2},
    ?FORALL({Handshake, Type}, ssl_msg(),
	    try 
                ssl_handshake:encode_handshake(
                  ssl_handshake:decode_handshake(SSLVersion, Type, msg_data(SSLVersion)), SSLVersion) of
                Handshake ->
                    true
            catch
                throw:#alert{} ->
                    true
            end
	   ).

ssl_msg() ->
    ?LET(M, oneof([{#hello_request{}, handshake_type(hello_request)},
                   {#client_hello{}, handshake_type(client_hello)},
		   {#server_hello{}, handshake_type(server_hello)}
		  ]), M).

msg_data(Version) ->
    Msgs = [MsgData || MsgData <- [hello_request(), ssl_v2client_hello(Version),
				   ssl_server_hello(Version)]],
    ?LET(M,oneof(Msgs), M).

hello_request() ->
    <<>>.

ssl_v2client_hello({Major, Minor} = Version) ->
    <<SuiteLen:16/unsigned-big-integer, Suites/binary>> = cipher_suites(Version),
    ?LET({ChallengeDataLen, ChallengeData},  challange_data(),
         <<Major:8/unsigned-big-integer, Minor:8/unsigned-big-integer,
           SuiteLen:16/unsigned-big-integer, 0:16/unsigned-big-integer, ChallengeDataLen:16/unsigned-big-integer, 
           Suites/binary, ChallengeData/binary>>).
challange_data() ->
    ?LET(Len, uint16(), 
         ?LET(Data, challange_data(Len), {Len, Data})).
challange_data(Len) ->
    crypto:rand_bytes(Len).
        
ssl_server_hello({Major, Minor} = Version) ->
    Comp_method = comp_method(Version),
    Session_ID = session_id(Version),
    Random =  crypto:rand_bytes(32),
    SID_length = size(Session_ID),
    ?LET(Cipher_suite, cipher_suite(Version),
	 <<Major:8/unsigned-big-integer, Minor:8/unsigned-big-integer, Random/binary,
	   SID_length:8/unsigned-big-integer, Session_ID:SID_length/binary,
	   Cipher_suite:2/binary, Comp_method:8/unsigned-big-integer>>).

handshake_type(hello_request) ->
    ?HELLO_REQUEST;
handshake_type(?HELLO_REQUEST) ->
    hello_request;
handshake_type(client_hello) ->
    ?CLIENT_HELLO;
handshake_type(?CLIENT_HELLO) ->
    client_hello;
handshake_type(server_hello) ->
    ?SERVER_HELLO;
handshake_type(?SERVER_HELLO) ->
    server_hello.
 
uint16() ->
    gen_byte(2).

gen_byte(N) when N>0 ->
    [gen_byte() || _ <- lists:seq(1,N)]. 

gen_byte() ->
    choose(0,255).

cipher_suites(SslVersion) ->
    Suites = ssl_cipher:suites(SslVersion),
    BinSuites = list_to_binary(Suites),
    Len = byte_size(BinSuites),
    <<Len:16/unsigned-big-integer, BinSuites/binary>>.

cipher_suite(SslVersion) ->
    Suites = ssl_cipher:suites(SslVersion),
    lists:nth(random:uniform(length(Suites)), Suites).

comp_method(_SslVersion) -> 
    ?NULL.

session_id(_SslVersion) ->
    crypto:rand_bytes(?NUM_OF_SESSION_ID_BYTES).
