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
-module(ssl_cert_SUITE).

%% Note: This directive should only be used in test suites.
-compile(export_all).
-include_lib("common_test/include/ct.hrl").

%%--------------------------------------------------------------------
%% Common Test interface functions -----------------------------------
%%--------------------------------------------------------------------

all() ->
    [
     {group, 'tlsv1.3'},
     {group, 'tlsv1.2'},
     {group, 'tlsv1.1'},
     {group, 'tlsv1'},
     {group, 'sslv3'},
     {group, 'dtlsv1.2'},
     {group, 'dtlsv1'}
    ].

groups() ->
    [
     {'tlsv1.3', [], tls_1_3_protocol_groups()}, 
     {'tlsv1.2', [], pre_tls_1_3_protocol_groups()},
     {'tlsv1.1', [], pre_tls_1_3_protocol_groups()},
     {'tlsv1', [], pre_tls_1_3_protocol_groups()},
     {'sslv3', [], ssl_protocol_groups()},
     {'dtlsv1.2', [], pre_tls_1_3_protocol_groups()},
     {'dtlsv1', [], pre_tls_1_3_protocol_groups()},
     {rsa, [], all_version_tests()},
     {ecdsa, [], all_version_tests()},
     {dsa, [], all_version_tests()},
     {rsa_1_3, [], all_version_tests() ++ tls_1_3_tests() ++ [unsupported_sign_algo_cert_client_auth]},
     {ecdsa_1_3, [], all_version_tests() ++ tls_1_3_tests()}
    ].

ssl_protocol_groups() ->
    [{group, rsa},
     {group, dsa}].

pre_tls_1_3_protocol_groups() ->
    [{group, rsa},
     {group, ecdsa},
     {group, dsa}].

tls_1_3_protocol_groups() ->
    [{group, rsa_1_3},
     {group, ecdsa_1_3}].

tls_1_3_tests() ->
    [
     hello_retry_request,
     custom_groups,
     hello_retry_client_auth,
     hello_retry_client_auth_empty_cert_accepted,
     hello_retry_client_auth_empty_cert_rejected
    ].

all_version_tests() ->
    [
     no_auth,
     auth,
     client_auth,
     client_auth_empty_cert_accepted,
     client_auth_empty_cert_rejected,
     client_auth_partial_chain,
     client_auth_allow_partial_chain,
     client_auth_do_not_allow_partial_chain,
     client_auth_partial_chain_fun_fail
    ].

init_per_suite(Config) ->
    catch crypto:stop(),
    try crypto:start() of
	ok ->
	    ssl_test_lib:clean_start(),
            Config
    catch _:_ ->
	    {skip, "Crypto did not start"}
    end.

end_per_suite(_Config) ->
    ssl:stop(),
    application:unload(ssl),
    application:stop(crypto).

init_per_group(Group, Config0) when Group == rsa;
                                    Group == rsa_1_3 ->
    Config = ssl_test_lib:make_rsa_cert(Config0),
    COpts = proplists:get_value(client_rsa_opts, Config),
    SOpts = proplists:get_value(server_rsa_opts, Config),
    [{client_cert_opts, COpts}, {server_cert_opts, SOpts} | 
     lists:delete(server_cert_opts, lists:delete(client_cert_opts, Config))];
init_per_group(Group, Config0) when Group == ecdsa;
                                    Group == ecdsa_1_3 ->

    PKAlg = crypto:supports(public_keys),
    case lists:member(ecdsa, PKAlg) andalso (lists:member(ecdh, PKAlg) orelse lists:member(dh, PKAlg)) of
        true ->
            Config = ssl_test_lib:make_ecdsa_cert(Config0),
            COpts = proplists:get_value(client_ecdsa_opts, Config),
            SOpts = proplists:get_value(server_ecdsa_opts, Config),
            [{client_cert_opts, COpts}, {server_cert_opts, SOpts} | 
             lists:delete(server_cert_opts, lists:delete(client_cert_opts, Config))];
        false ->
            {skip, "Missing EC crypto support"}
    end;

init_per_group(Group, Config0) when Group == dsa ->
    PKAlg = crypto:supports(public_keys),
    case lists:member(dss, PKAlg) andalso lists:member(dh, PKAlg) of
        true ->
            Config = ssl_test_lib:make_dsa_cert(Config0),    
            COpts = proplists:get_value(client_dsa_opts, Config),
            SOpts = proplists:get_value(server_dsa_opts, Config),
            [{client_cert_opts, COpts}, {server_cert_opts, SOpts} | 
             lists:delete(server_cert_opts, lists:delete(client_cert_opts, Config))];
        false ->
            {skip, "Missing DSS crypto support"}
    end;    
init_per_group(GroupName, Config) ->
    case ssl_test_lib:is_tls_version(GroupName) of
	true ->
	    case ssl_test_lib:sufficient_crypto_support(GroupName) of
		true ->
		    [{client_type, erlang},
                     {server_type, erlang}, {version, GroupName} 
                     | ssl_test_lib:init_tls_version(GroupName, Config)];
		false ->
		    {skip, "Missing crypto support"}
	    end;
	_ ->
	    ssl:start(),
	    Config
    end.

end_per_group(GroupName, Config) ->
    case ssl_test_lib:is_tls_version(GroupName) of
        true ->
            ssl_test_lib:clean_tls_version(Config);
        false ->
            Config
    end.

init_per_testcase(_TestCase, Config) ->
    ssl_test_lib:ct_log_supported_protocol_versions(Config),
    ct:timetrap({seconds, 10}),
    Config.

end_per_testcase(_TestCase, Config) ->     
    Config.

%%--------------------------------------------------------------------
%% Test Cases --------------------------------------------------------
%%--------------------------------------------------------------------

no_auth() ->
     [{doc,"Test connection without authentication"}].

no_auth(Config) ->
    ClientOpts = [{verify, verify_none} | ssl_test_lib:ssl_options(client_cert_opts, Config)],
    ServerOpts =  [{verify, verify_none} | ssl_test_lib:ssl_options(server_cert_opts, Config)],
    
    ssl_test_lib:basic_test(ClientOpts, ServerOpts, Config).
%%--------------------------------------------------------------------
auth() ->
     [{doc,"Test connection with mutual authentication"}].

auth(Config) ->
    ClientOpts = [{verify, verify_peer} | ssl_test_lib:ssl_options(client_cert_opts, Config)],
    ServerOpts =  [{verify, verify_peer} | ssl_test_lib:ssl_options(server_cert_opts, Config)],
    
    ssl_test_lib:basic_test(ClientOpts, ServerOpts, Config).
%%--------------------------------------------------------------------
client_auth() ->
    [{doc, "Test client authentication."}].

client_auth(Config) ->
    ClientOpts = ssl_test_lib:ssl_options(client_cert_opts, Config),
    ServerOpts0 = ssl_test_lib:ssl_options(server_cert_opts, Config),
    ServerOpts = [{verify, verify_peer},
                  {fail_if_no_peer_cert, true} | ServerOpts0],
    
    ssl_test_lib:basic_test(ClientOpts, ServerOpts, Config).
%%--------------------------------------------------------------------
client_auth_empty_cert_accepted() ->
    [{doc,"Test client authentication when client sends an empty certificate and " 
      "fail_if_no_peer_cert is set to false."}].

client_auth_empty_cert_accepted(Config) ->
    ClientOpts = proplists:delete(keyfile,
                                  proplists:delete(certfile, 
                                                   ssl_test_lib:ssl_options(client_cert_opts, Config))),
    ServerOpts0 = ssl_test_lib:ssl_options(server_cert_opts, Config),
    ServerOpts = [{verify, verify_peer},
                  {fail_if_no_peer_cert, false} | ServerOpts0],
    ssl_test_lib:basic_test(ClientOpts, ServerOpts, Config).
%%--------------------------------------------------------------------
client_auth_empty_cert_rejected() ->
     [{doc,"Test client authentication when client sends an empty certificate and " 
       "fail_if_no_peer_cert is set to true."}].

client_auth_empty_cert_rejected(Config) ->
    ServerOpts = [{verify, verify_peer}, {fail_if_no_peer_cert, true}
		  | ssl_test_lib:ssl_options(server_cert_opts, Config)],
    ClientOpts0 = ssl_test_lib:ssl_options([], Config),
    %% Delete Client Cert and Key
    ClientOpts1 = proplists:delete(certfile, ClientOpts0),
    ClientOpts = proplists:delete(keyfile, ClientOpts1),
    
    Version = proplists:get_value(version,Config),
    case Version of
        'tlsv1.3' ->
            ssl_test_lib:basic_alert(ClientOpts, ServerOpts, Config, certificate_required);
        _ ->
            ssl_test_lib:basic_alert(ClientOpts, ServerOpts, Config, handshake_failure)
    end.
%%--------------------------------------------------------------------
client_auth_partial_chain() ->
    [{doc, "Client sends an incompleate chain, by default not acceptable."}].

client_auth_partial_chain(Config) when is_list(Config) ->
    ServerOpts = [{verify, verify_peer}, {fail_if_no_peer_cert, true}
		  | ssl_test_lib:ssl_options(server_cert_opts, Config)],
    ClientOpts0 = ssl_test_lib:ssl_options(client_cert_opts, Config),
    {ok, ClientCAs} = file:read_file(proplists:get_value(cacertfile, ClientOpts0)),
    [{_,RootCA,_} | _] = public_key:pem_decode(ClientCAs),
    ClientOpts =  [{cacerts, [RootCA]} |
                   proplists:delete(cacertfile, ClientOpts0)],
    ssl_test_lib:basic_alert(ClientOpts, ServerOpts, Config, unknown_ca).
    
%%--------------------------------------------------------------------
client_auth_allow_partial_chain() ->
    [{doc, "Server trusts intermediat CA and accepts a partial chain. (partial_chain option)"}].

client_auth_allow_partial_chain(Config) when is_list(Config) ->
    ServerOpts0 = [{verify, verify_peer}, {fail_if_no_peer_cert, true}
		  | ssl_test_lib:ssl_options(server_cert_opts, Config)],
    ClientOpts = ssl_test_lib:ssl_options(client_cert_opts, Config),
    {ok, ClientCAs} = file:read_file(proplists:get_value(cacertfile, ClientOpts)),
    [{_,_,_}, {_, IntermidiateCA, _} | _] = public_key:pem_decode(ClientCAs),

    PartialChain =  fun(CertChain) ->
			    case lists:member(IntermidiateCA, CertChain) of
				true ->
				    {trusted_ca, IntermidiateCA};
				false ->
				    unknown_ca
			    end
		    end,
    ServerOpts = [{cacerts, [IntermidiateCA]},
                  {partial_chain, PartialChain} |
                  proplists:delete(cacertfile, ServerOpts0)],

    ssl_test_lib:basic_test(ClientOpts, ServerOpts, Config).

 %%--------------------------------------------------------------------
client_auth_do_not_allow_partial_chain() ->
    [{doc, "Server does not accept the chain sent by the client as ROOT CA is unkown, "
      "and we do not choose to trust the intermediate CA. (partial_chain option)"}].

client_auth_do_not_allow_partial_chain(Config) when is_list(Config) ->
    ServerOpts0 = [{verify, verify_peer}, {fail_if_no_peer_cert, true}
		  | ssl_test_lib:ssl_options(server_cert_opts, Config)],
    ClientOpts = ssl_test_lib:ssl_options(client_cert_opts, Config),
    {ok, ServerCAs} = file:read_file(proplists:get_value(cacertfile, ServerOpts0)),
    [{_,_,_}, {_, IntermidiateCA, _} | _] = public_key:pem_decode(ServerCAs),

    PartialChain =  fun(_CertChain) ->
			    unknown_ca
		    end,
    ServerOpts = [{cacerts, [IntermidiateCA]},
                  {partial_chain, PartialChain} |
                  proplists:delete(cacertfile, ServerOpts0)],
    ssl_test_lib:basic_alert(ClientOpts, ServerOpts, Config, unknown_ca).
    
 %%--------------------------------------------------------------------
client_auth_partial_chain_fun_fail() ->
    [{doc, "If parial_chain fun crashes, treat it as if it returned unkown_ca"}].

client_auth_partial_chain_fun_fail(Config) when is_list(Config) ->
    ServerOpts0 = [{verify, verify_peer}, {fail_if_no_peer_cert, true}
                   | ssl_test_lib:ssl_options(server_cert_opts, Config)],
    ClientOpts = ssl_test_lib:ssl_options(client_cert_opts, Config),

    {ok, ServerCAs} = file:read_file(proplists:get_value(cacertfile, ServerOpts0)),
    [{_,_,_}, {_, IntermidiateCA, _} | _] = public_key:pem_decode(ServerCAs),

    PartialChain =  fun(_CertChain) ->
                            true = false %% crash on purpose
		    end,
    ServerOpts = [{cacerts, [IntermidiateCA]},
                  {partial_chain, PartialChain} |
                  proplists:delete(cacertfile, ServerOpts0)],
    
    ssl_test_lib:basic_alert(ClientOpts, ServerOpts, Config, unknown_ca).

%%--------------------------------------------------------------------
verify_fun_always_run_client() ->
    [{doc,"Verify that user verify_fun is always run (for valid and "
      "valid_peer not only unknown_extension)"}].

verify_fun_always_run_client(Config) when is_list(Config) ->
    ClientOpts0 =  ssl_test_lib:ssl_options(client_cert_opts, Config),
    ServerOpts =  ssl_test_lib:ssl_options(server_cert_opts, Config),   
    %% If user verify fun is called correctly we fail the connection.
    %% otherwise we cannot tell this case apart form where we miss
    %% to call users verify fun
    FunAndState =  {fun(_,{extension, _}, UserState) ->
			    {unknown, UserState};
		       (_, valid, [ChainLen]) ->
			    {valid, [ChainLen + 1]};
		       (_, valid_peer, [1]) ->
			    {fail, "verify_fun_was_always_run"};
		       (_, valid_peer, UserState) ->
			    {valid, UserState}
		    end, [0]},
    
    ClientOpts = [{verify, verify_peer},
                  {verify_fun, FunAndState}
                  | ClientOpts0],
    
    ssl_test_lib:basic_alert(ClientOpts, ServerOpts, Config, handshake_failure).

   
%%--------------------------------------------------------------------
verify_fun_always_run_server() ->
    [{doc,"Verify that user verify_fun is always run (for valid and valid_peer "
      "not only unknown_extension)"}].
verify_fun_always_run_server(Config) when is_list(Config) ->
    ClientOpts =  ssl_test_lib:ssl_options(client_cert_opts, Config),
    ServerOpts0 =  ssl_test_lib:ssl_options(server_rsa_verify_opts, Config),

    %% If user verify fun is called correctly we fail the connection.
    %% otherwise we cannot tell this case apart form where we miss
    %% to call users verify fun
    FunAndState =  {fun(_,{extension, _}, UserState) ->
			    {unknown, UserState};
		       (_, valid, [ChainLen]) ->
			    {valid, [ChainLen + 1]};
		       (_, valid_peer, [1]) ->
			    {fail, "verify_fun_was_always_run"};
		       (_, valid_peer, UserState) ->
			    {valid, UserState}
		    end, [0]},
    ServerOpts =   [{verify, verify_peer},
                    {verify_fun, FunAndState} |
                    ServerOpts0],
    
    ssl_test_lib:basic_alert(ClientOpts, ServerOpts, Config, handshake_failure).

%%--------------------------------------------------------------------
%% TLS 1.3 Test Cases --------------------------------------------------------
%%--------------------------------------------------------------------

hello_retry_request() ->
    [{doc,"Test that ssl server can request a new group when the client's first key share"
      "is not supported"}].

hello_retry_request(Config) ->
    ClientOpts0 = ssl_test_lib:ssl_options(client_cert_opts, Config),
    ServerOpts0 = ssl_test_lib:ssl_options(server_cert_opts, Config),
    ServerOpts = [{versions, ['tlsv1.2','tlsv1.3']},
                  {supported_groups, [x448, x25519]}|ServerOpts0],
    ClientOpts = [{versions, ['tlsv1.2','tlsv1.3']},
                  {supported_groups, [secp256r1, x25519]}|ClientOpts0],
    ssl_test_lib:basic_test(ClientOpts, ServerOpts, Config).
%%--------------------------------------------------------------------
custom_groups() ->
    [{doc,"Test that ssl server can select a common group for key-exchange"}].

custom_groups(Config) ->
    ClientOpts0 = ssl_test_lib:ssl_options(client_cert_opts, Config),
    ServerOpts0 = ssl_test_lib:ssl_options(server_cert_opts, Config),

    %% Set versions
    ServerOpts = [{versions, ['tlsv1.2','tlsv1.3']},
                  {supported_groups, [x448, secp256r1, secp384r1]}|ServerOpts0],
    ClientOpts1 = [{versions, ['tlsv1.2','tlsv1.3']}|ClientOpts0],
    ClientOpts = [{supported_groups,[secp384r1, secp256r1, x25519]}|ClientOpts1],
    ssl_test_lib:basic_test(ClientOpts, ServerOpts, Config).

%%--------------------------------------------------------------------
%% Triggers a Server Alert as ssl client does not have a certificate with a
%% signature algorithm supported by the server (signature_algorithms_cert extension
%% of CertificateRequest does not contain the algorithm of the client certificate).
%% ssl client sends an empty certificate.
unsupported_sign_algo_cert_client_auth() ->
     [{doc,"TLS 1.3: Test client authentication with unsupported signature_algorithm_cert"}].

unsupported_sign_algo_cert_client_auth(Config) ->
    ClientOpts0 = ssl_test_lib:ssl_options(client_cert_opts, Config),
    ServerOpts0 = ssl_test_lib:ssl_options(server_cert_opts, Config),
    ServerOpts = [{versions, ['tlsv1.2','tlsv1.3']},
                  {verify, verify_peer},
                  %% Skip rsa_pkcs1_sha256!
                  {signature_algs, [rsa_pkcs1_sha384, rsa_pss_rsae_sha256]},
                  {fail_if_no_peer_cert, true}|ServerOpts0],
    ClientOpts = [{versions, ['tlsv1.2','tlsv1.3']}|ClientOpts0],
    ssl_test_lib:basic_alert(ClientOpts, ServerOpts, Config, handshake_failure).
%%--------------------------------------------------------------------
hello_retry_client_auth() ->
    [{doc, "TLS 1.3 (HelloRetryRequest): Test client authentication."}].

hello_retry_client_auth(Config) ->
    ClientOpts0 = ssl_test_lib:ssl_options(client_cert_opts, Config),
    ServerOpts0 = ssl_test_lib:ssl_options(server_cert_opts, Config),
    ServerOpts1 = [{versions, ['tlsv1.2','tlsv1.3']},
                  {supported_groups, [x448, x25519]}|ServerOpts0],
    ClientOpts = [{versions, ['tlsv1.2','tlsv1.3']},
                  {supported_groups, [secp256r1, x25519]}|ClientOpts0],
    ServerOpts = [{verify, verify_peer},
                  {fail_if_no_peer_cert, true} | ServerOpts1],
    
    ssl_test_lib:basic_test(ClientOpts, ServerOpts, Config).
%%--------------------------------------------------------------------
hello_retry_client_auth_empty_cert_accepted() ->
     [{doc,"TLS 1.3 (HelloRetryRequest): Test client authentication when client sends an empty " 
       "certificate and fail_if_no_peer_cert is set to true."}].

hello_retry_client_auth_empty_cert_accepted(Config) ->
    ClientOpts0 = ssl_test_lib:ssl_options(client_cert_opts, Config),
    %% Delete Client Cert and Key
    ClientOpts1 = proplists:delete(certfile, ClientOpts0),
    ClientOpts2 = proplists:delete(keyfile, ClientOpts1),

    ServerOpts0 = ssl_test_lib:ssl_options(server_cert_opts, Config),
    %% Set versions
    ServerOpts = [{versions, ['tlsv1.2','tlsv1.3']},
                  {verify, verify_peer},
                  {fail_if_no_peer_cert, false},
                  {supported_groups, [x448, x25519]}|ServerOpts0],
    ClientOpts = [{versions, ['tlsv1.2','tlsv1.3']},
                  {supported_groups, [secp256r1, x25519]}|ClientOpts2],
    ssl_test_lib:basic_test(ClientOpts, ServerOpts, Config).
%%--------------------------------------------------------------------
hello_retry_client_auth_empty_cert_rejected() ->
     [{doc,"TLS 1.3 (HelloRetryRequest): Test client authentication when client "
       "sends an empty certificate and fail_if_no_peer_cert is set to true."}].

hello_retry_client_auth_empty_cert_rejected(Config) ->
    ClientOpts0 = ssl_test_lib:ssl_options(client_cert_opts, Config),
    %% Delete Client Cert and Key
    ClientOpts1 = proplists:delete(certfile, ClientOpts0),
    ClientOpts2 = proplists:delete(keyfile, ClientOpts1),

    ServerOpts0 = ssl_test_lib:ssl_options(server_cert_opts, Config),
    %% Set versions
    ServerOpts = [{versions, ['tlsv1.2','tlsv1.3']},
                  {verify, verify_peer},
                  {fail_if_no_peer_cert, true},
                  {supported_groups, [x448, x25519]}|ServerOpts0],
    ClientOpts = [{versions, ['tlsv1.2','tlsv1.3']},
                  {supported_groups, [secp256r1, x25519]}|ClientOpts2],
   
    ssl_test_lib:basic_alert(ClientOpts, ServerOpts, Config, certificate_required).

    
