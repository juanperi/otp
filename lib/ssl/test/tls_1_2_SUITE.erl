%%
%% %CopyrightBegin%
%%
%% Copyright Ericsson AB 2019-2019. All Rights Reserved.
%%
%% Licensed under the Apache License, Version 2.0 (the "License");
%% you may not use this file except in compliance with the License.
%% You may obtain a copy of the License at
%%
%%     http://www.apache.org/licenses/LICENSE-2.0
%%
%% Unless required by applicable law or agreed to in writing, software
%% distributed under the License is distributed on an "AS IS" BASIS,
%% WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
%% See the License for the specific language governing permissions and
%% limitations under the License.
%%
%% %CopyrightEnd%
%%

%%

-module(tls_1_2_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("public_key/include/public_key.hrl").

%%--------------------------------------------------------------------
%% Common Test interface functions -----------------------------------
%%--------------------------------------------------------------------
all() ->
    [
     {group, 'tlsv1.2'},
     {group, 'tlsv1.1'},
     {group, 'tlsv1'},
     {group, 'sslv3'},
     {group, 'dtlsv1.2'},
     {group, 'dtlsv1'}
    ].

groups() ->
    [
     {'tlsv1.2', [], all_protocol_groups()},
     {'tlsv1.1', [], all_protocol_groups()},
     {'tlsv1', [], all_protocol_groups()},
     {'sslv3', [], all_protocol_groups()},
     {'dtlsv1.2', [], all_protocol_groups()},
     {'dtlsv1', [], all_protocol_groups()},
     {active, [], tests()},
     {active_once, [], tests()},
     {passive, [], tests()},
     {error_handling, [],error_handling_tests()}
    ].

all_protocol_groups() ->
    [{group, active},
     {group, passive},
     {group, active_once},
     {group, error_handling}].

tests() ->
    [verify_peer,
     verify_none,
     server_require_peer_cert_ok,
     server_require_peer_cert_fail,
     server_require_peer_cert_empty_ok,
     server_require_peer_cert_partial_chain,
     server_require_peer_cert_allow_partial_chain,
     server_require_peer_cert_do_not_allow_partial_chain,
     server_require_peer_cert_partial_chain_fun_fail,
     verify_fun_always_run_client,
     verify_fun_always_run_server,
     cert_expired,
     invalid_signature_client,
     invalid_signature_server,
     extended_key_usage_verify_both,
     extended_key_usage_verify_server,
     critical_extension_verify_client,
     critical_extension_verify_server,
     critical_extension_verify_none,
     customize_hostname_check,
     incomplete_chain
    ].

error_handling_tests()->
    [client_with_cert_cipher_suites_handshake,
     server_verify_no_cacerts,
     unknown_server_ca_fail,
     unknown_server_ca_accept_verify_none,
     unknown_server_ca_accept_verify_peer,
     unknown_server_ca_accept_backwardscompatibility,
     no_authority_key_identifier,
     no_authority_key_identifier_keyEncipherment].

init_per_suite(Config) ->
    catch crypto:stop(),
    try crypto:start() of
	ok ->
            ssl_test_lib:clean_start(), 
            ssl_test_lib:make_rsa_cert(Config)            
    catch _:_ ->
	    {skip, "Crypto did not start"}
    end.

end_per_suite(_Config) ->
    ssl:stop(),
    application:stop(crypto).

init_per_group(active, Config) ->
    [{active, true}, {receive_function, send_recv_result_active} | Config];
init_per_group(active_once, Config) ->
    [{active, once}, {receive_function, send_recv_result_active_once} | Config];
init_per_group(passive, Config) ->
    [{active, false}, {receive_function, send_recv_result} | Config];
init_per_group(error_handling, Config) ->
    [{active, false}, {receive_function, send_recv_result} | Config];
init_per_group(GroupName, Config) ->
    case ssl_test_lib:is_tls_version(GroupName) of
	true ->
	    case ssl_test_lib:sufficient_crypto_support(GroupName) of
		true ->
		    [{version, GroupName} | ssl_test_lib:init_tls_version(GroupName, Config)];
		false ->
		    {skip, "Missing crypto support"}
	    end
    end.

end_per_group(GroupName, Config) ->
       case ssl_test_lib:is_tls_version(GroupName) of
        true ->
            ssl_test_lib:clean_tls_version(Config);
        false ->
            Config
    end.

init_per_testcase(_TestCase, Config) ->
    ssl:stop(),
    ssl:start(),
    ssl_test_lib:ct_log_supported_protocol_versions(Config),
    ct:timetrap({seconds, 10}),
    Config.

end_per_testcase(_TestCase, Config) ->     
    Config.

%%--------------------------------------------------------------------
%% Test Cases --------------------------------------------------------
%%--------------------------------------------------------------------
