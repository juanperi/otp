%%
%% %CopyrightBegin%
%% 
%% Copyright Ericsson AB 2015-2015. All Rights Reserved.
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

-module(ssl_eqc_SUITE).

-compile(export_all).

%%--------------------------------------------------------------------
%% Common Test interface functions -----------------------------------
%%--------------------------------------------------------------------

all() -> 
    [
     handshake_encode_decode
    ].

%%--------------------------------------------------------------------
init_per_suite(Config) ->
    Config.
end_per_suite(Config) ->
    Config.

init_per_group(_GroupName, Config) ->
    Config.

end_per_group(_,Config) ->
    Config.

init_per_testcase(_, Config0) ->
    Config0.

end_per_testcase(_TestCase, Config) ->
    Config.

%%--------------------------------------------------------------------
%% Test Cases --------------------------------------------------------
%%--------------------------------------------------------------------

handshake_encode_decode(Config) when is_list(Config) ->
    true = eqc:quickcheck(
	     ssl_eqc_handshake_encode_decode:prop_ssl_decode_encode()).
