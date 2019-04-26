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

-module(ssl_to_openssl_cipher_suite_SUITE).

%% Note: This directive should only be used in test suites.
-compile(export_all).

-include_lib("common_test/include/ct.hrl").

%%--------------------------------------------------------------------
%% Common Test interface functions -----------------------------------
%%--------------------------------------------------------------------
all() -> 
    ssl_cipher_suite_SUITE:all().

groups() ->
    %% TODO: SRP interop tests
    %%ssl_cipher_suite_SUITE:groups(),
    [
     {'tlsv1.2', [], kex()},
     {'tlsv1.1', [], kex()},
     {'tlsv1', [], kex()},
     {'sslv3', [], kex()},
     {'dtlsv1.2', [], kex()},
     {'dtlsv1', [], kex()},
     {dhe_rsa, [],[dhe_rsa_3des_ede_cbc, 
                   dhe_rsa_aes_128_cbc,
                   dhe_rsa_aes_256_cbc,
                   dhe_rsa_chacha20_poly1305
                  ]},
     {ecdhe_rsa, [], [ecdhe_rsa_3des_ede_cbc, 
                      ecdhe_rsa_aes_128_cbc,
                      ecdhe_rsa_aes_128_gcm,
                      ecdhe_rsa_aes_256_cbc,
                      ecdhe_rsa_aes_256_gcm,
                      ecdhe_rsa_chacha20_poly1305
                    ]},
     {ecdhe_ecdsa, [],[ecdhe_ecdsa_rc4_128, 
                       ecdhe_ecdsa_3des_ede_cbc, 
                       ecdhe_ecdsa_aes_128_cbc,
                       ecdhe_ecdsa_aes_128_gcm,
                       ecdhe_ecdsa_aes_256_cbc,
                       ecdhe_ecdsa_aes_256_gcm,
                       ecdhe_ecdsa_chacha20_poly1305
                      ]},
     {rsa, [], [rsa_3des_ede_cbc, 
                rsa_aes_128_cbc,
                rsa_aes_256_cbc,
                rsa_rc4_128
               ]},
     {dhe_dss, [], [dhe_dss_3des_ede_cbc, 
                    dhe_dss_aes_128_cbc,
                    dhe_dss_aes_256_cbc]},
     %% {srp_rsa, [], [srp_rsa_3des_ede_cbc, 
     %%                srp_rsa_aes_128_cbc,
     %%                srp_rsa_aes_256_cbc]},
     %% {srp_dss, [], [srp_dss_3des_ede_cbc, 
     %%                srp_dss_aes_128_cbc,
     %%                srp_dss_aes_256_cbc]},
     {rsa_psk, [], [rsa_psk_3des_ede_cbc,                    
                    rsa_psk_rc4_128,
                    rsa_psk_aes_128_cbc,
                    rsa_psk_aes_256_cbc
                   ]},
     {dh_anon, [], [dh_anon_rc4_128,
                    dh_anon_3des_ede_cbc, 
                    dh_anon_aes_128_cbc,
                    dh_anon_aes_128_gcm,
                    dh_anon_aes_256_cbc,
                    dh_anon_aes_256_gcm]},
     {ecdh_anon, [], [ecdh_anon_3des_ede_cbc, 
                      ecdh_anon_aes_128_cbc,
                      ecdh_anon_aes_256_cbc
                     ]},     
     %% {srp_anon, [], [srp_anon_3des_ede_cbc, 
     %%                 srp_anon_aes_128_cbc,
     %%                 srp_anon_aes_256_cbc]},
     %% {psk, [], [psk_3des_ede_cbc,                    
     %%            psk_rc4_128,
     %%            psk_aes_128_cbc,
     %%            psk_aes_128_ccm,
     %%            psk_aes_128_ccm_8,
     %%            psk_aes_256_cbc,
     %%            psk_aes_256_ccm,
     %%            psk_aes_256_ccm_8
     %%           ]},
     {dhe_psk, [], [dhe_psk_3des_ede_cbc,                    
                    dhe_psk_rc4_128,
                    dhe_psk_aes_128_cbc,
                    dhe_psk_aes_128_ccm,
                    dhe_psk_aes_128_ccm_8,
                    dhe_psk_aes_256_cbc,
                    dhe_psk_aes_256_ccm,
                    dhe_psk_aes_256_ccm_8
               ]},
     {ecdhe_psk, [], [ecdhe_psk_3des_ede_cbc,                    
                     ecdhe_psk_rc4_128,
                     ecdhe_psk_aes_128_cbc,
                     ecdhe_psk_aes_128_ccm,
                     ecdhe_psk_aes_128_ccm_8,
                     ecdhe_psk_aes_256_cbc
               ]}
    ].


kex() ->
     rsa() ++ ecdsa() ++ dss() ++ anonymous().

rsa() ->
    [{group, dhe_rsa},
     {group, ecdhe_rsa},
     {group, rsa},
     %% {group, srp_rsa},
     {group, rsa_psk}
    ].

ecdsa() ->
    [{group, ecdhe_ecdsa}].
    
dss() ->
    [{group, dhe_dss}
     %%{group, srp_dss}
    ].

anonymous() ->
    [{group, dh_anon},
     {group, ecdh_anon},
     %% {group, psk},
     {group, dhe_psk},
     {group, ecdhe_psk}
     %%{group, srp_anon}
    ].

init_per_suite(Config) ->
    ssl_cipher_suite_SUITE:init_per_suite(Config).

end_per_suite(Config) ->
    ssl_cipher_suite_SUITE:end_per_suite(Config).

%%--------------------------------------------------------------------
init_per_group(GroupName, Config) ->
       case ssl_test_lib:is_tls_version(GroupName) of
           true ->
               case ssl_test_lib:supports_ssl_tls_version(GroupName) of
                   true ->
                       ssl_cipher_suite_SUITE:init_per_group(GroupName, Config);
                   false ->
                       {skip, {openssl_does_not_support, GroupName}}
               end;  
           false ->
               ssl_cipher_suite_SUITE:init_per_group(GroupName, Config)
       end.

end_per_group(GroupName, Config) ->
    ssl_cipher_suite_SUITE:end_per_group(GroupName, Config).

init_per_testcase(TestCase, Config) ->
    ssl_cipher_suite_SUITE:init_per_testcase(TestCase, Config).

end_per_testcase(TestCase, Config) ->
    ssl_cipher_suite_SUITE:end_per_testcase(TestCase, Config).

%%--------------------------------------------------------------------
%% Test Cases --------------------------------------------------------
%%--------------------------------------------------------------------

%%--------------------------------------------------------------------
%% SRP --------------------------------------------------------
%%--------------------------------------------------------------------
srp_rsa_3des_ede_cbc(Config) when is_list(Config) ->
    run_ciphers_test(srp_rsa, '3des_ede_cbc', Config).                 
    
srp_rsa_aes_128_cbc(Config) when is_list(Config) ->
   run_ciphers_test(srp_rsa, 'aes_128_cbc', Config).             

srp_rsa_aes_256_cbc(Config) when is_list(Config) ->
   run_ciphers_test(srp_rsa, 'aes_256_cbc', Config).             

srp_dss_3des_ede_cbc(Config) when is_list(Config) ->
    run_ciphers_test(srp_dss, '3des_ede_cbc', Config).                 
    
srp_dss_aes_128_cbc(Config) when is_list(Config) ->
   run_ciphers_test(srp_dss, 'aes_128_cbc', Config).             

srp_dss_aes_256_cbc(Config) when is_list(Config) ->
   run_ciphers_test(srp_dss, 'aes_256_cbc', Config).     

%%--------------------------------------------------------------------
%% PSK --------------------------------------------------------
%%--------------------------------------------------------------------
rsa_psk_3des_ede_cbc(Config) when is_list(Config) ->
    run_ciphers_test(rsa_psk, '3des_ede_cbc', Config).            

rsa_psk_aes_128_cbc(Config) when is_list(Config) ->
    run_ciphers_test(rsa_psk, 'aes_128_cbc', Config).             

rsa_psk_aes_128_ccm(Config) when is_list(Config) ->
    run_ciphers_test(rsa_psk, 'aes_128_ccm', Config).             

rsa_psk_aes_128_ccm_8(Config) when is_list(Config) ->
    run_ciphers_test(rsa_psk, 'aes_128_ccm_8', Config).             

rsa_psk_aes_256_cbc(Config) when is_list(Config) ->
    run_ciphers_test(rsa_psk, 'aes_256_cbc', Config). 

rsa_psk_aes_256_ccm(Config) when is_list(Config) ->
    run_ciphers_test(rsa_psk, 'aes_256_ccm', Config).             

rsa_psk_aes_256_ccm_8(Config) when is_list(Config) ->
    run_ciphers_test(rsa_psk, 'aes_256_ccm_8', Config).             
     
rsa_psk_rc4_128(Config) when is_list(Config) ->
    run_ciphers_test(rsa_psk, 'rc4_128', Config).    
         
%%--------------------------------------------------------------------
%% RSA --------------------------------------------------------
%%--------------------------------------------------------------------
rsa_des_cbc(Config) when is_list(Config) ->
    run_ciphers_test(rsa, 'des_cbc', Config).            

rsa_3des_ede_cbc(Config) when is_list(Config) ->
    run_ciphers_test(rsa, '3des_ede_cbc', Config).            

rsa_aes_128_cbc(Config) when is_list(Config) ->
    run_ciphers_test(rsa, 'aes_128_cbc', Config).             

rsa_aes_256_cbc(Config) when is_list(Config) ->
    run_ciphers_test(rsa, 'aes_256_cbc', Config).

rsa_aes_128_gcm(Config) when is_list(Config) ->
    run_ciphers_test(rsa, 'aes_128_gcm', Config).             

rsa_aes_256_gcm(Config) when is_list(Config) ->
    run_ciphers_test(rsa, 'aes_256_gcm', Config).

rsa_rc4_128(Config) when is_list(Config) ->
    run_ciphers_test(rsa, 'rc4_128', Config).    
%%--------------------------------------------------------------------
%% DHE_RSA --------------------------------------------------------
%%--------------------------------------------------------------------
dhe_rsa_3des_ede_cbc(Config) when is_list(Config) ->
    run_ciphers_test(dhe_rsa, '3des_ede_cbc', Config).         

dhe_rsa_aes_128_cbc(Config) when is_list(Config) ->
    run_ciphers_test(dhe_rsa, 'aes_128_cbc', Config).   

dhe_rsa_aes_128_gcm(Config) when is_list(Config) ->
    run_ciphers_test(dhe_rsa, 'aes_128_gcm', Config).   

dhe_rsa_aes_256_cbc(Config) when is_list(Config) ->
    run_ciphers_test(dhe_rsa, 'aes_256_cbc', Config).   

dhe_rsa_aes_256_gcm(Config) when is_list(Config) ->
    run_ciphers_test(dhe_rsa, 'aes_256_gcm', Config).

dhe_rsa_chacha20_poly1305(Config) when is_list(Config) ->
    run_ciphers_test(dhe_rsa, 'chacha20_poly1305', Config).
%%--------------------------------------------------------------------
%% ECDHE_RSA --------------------------------------------------------
%%--------------------------------------------------------------------
ecdhe_rsa_3des_ede_cbc(Config) when is_list(Config) ->
    run_ciphers_test(ecdhe_rsa, '3des_ede_cbc', Config).         

ecdhe_rsa_aes_128_cbc(Config) when is_list(Config) ->
    run_ciphers_test(ecdhe_rsa, 'aes_128_cbc', Config).         

ecdhe_rsa_aes_128_gcm(Config) when is_list(Config) ->
    run_ciphers_test(ecdhe_rsa, 'aes_128_gcm', Config).         

ecdhe_rsa_aes_256_cbc(Config) when is_list(Config) ->
    run_ciphers_test(ecdhe_rsa, 'aes_256_cbc', Config).   

ecdhe_rsa_aes_256_gcm(Config) when is_list(Config) ->
    run_ciphers_test(ecdhe_rsa, 'aes_256_gcm', Config).   

ecdhe_rsa_rc4_128(Config) when is_list(Config) ->
    run_ciphers_test(ecdhe_rsa, 'rc4_128', Config).      

ecdhe_rsa_chacha20_poly1305(Config) when is_list(Config) ->
    run_ciphers_test(ecdhe_rsa, 'chacha20_poly1305', Config).

%%--------------------------------------------------------------------
%% ECDHE_ECDSA --------------------------------------------------------
%%--------------------------------------------------------------------
ecdhe_ecdsa_rc4_128(Config) when is_list(Config) ->
    run_ciphers_test(ecdhe_ecdsa, 'rc4_128', Config).         

ecdhe_ecdsa_3des_ede_cbc(Config) when is_list(Config) ->
    run_ciphers_test(ecdhe_ecdsa, '3des_ede_cbc', Config).         

ecdhe_ecdsa_aes_128_cbc(Config) when is_list(Config) ->
    run_ciphers_test(ecdhe_ecdsa, 'aes_128_cbc', Config).         

ecdhe_ecdsa_aes_128_gcm(Config) when is_list(Config) ->
    run_ciphers_test(ecdhe_ecdsa, 'aes_128_gcm', Config).         

ecdhe_ecdsa_aes_256_cbc(Config) when is_list(Config) ->
    run_ciphers_test(ecdhe_ecdsa, 'aes_256_cbc', Config).   

ecdhe_ecdsa_aes_256_gcm(Config) when is_list(Config) ->
    run_ciphers_test(ecdhe_ecdsa, 'aes_256_gcm', Config).   

ecdhe_ecdsa_chacha20_poly1305(Config) when is_list(Config) ->
    run_ciphers_test(ecdhe_ecdsa, 'chacha20_poly1305', Config).
%%--------------------------------------------------------------------
%% DHE_DSS --------------------------------------------------------
%%--------------------------------------------------------------------
dhe_dss_des_cbc(Config) when is_list(Config) ->
    run_ciphers_test(dhe_dss, 'des_cbc', Config).            

dhe_dss_3des_ede_cbc(Config) when is_list(Config) ->
    run_ciphers_test(dhe_dss, '3des_ede_cbc', Config).            

dhe_dss_aes_128_cbc(Config) when is_list(Config) ->
    run_ciphers_test(dhe_dss, 'aes_128_cbc', Config).             

dhe_dss_aes_256_cbc(Config) when is_list(Config) ->
    run_ciphers_test(dhe_dss, 'aes_256_cbc', Config).

dhe_dss_aes_128_gcm(Config) when is_list(Config) ->
    run_ciphers_test(dhe_dss, 'aes_128_gcm', Config).             

dhe_dss_aes_256_gcm(Config) when is_list(Config) ->
    run_ciphers_test(dhe_dss, 'aes_256_gcm', Config).

%%--------------------------------------------------------------------
%% Anonymous --------------------------------------------------------
%%--------------------------------------------------------------------
dh_anon_3des_ede_cbc(Config) when is_list(Config) ->
    run_ciphers_test(dh_anon, '3des_ede_cbc', Config).         

dh_anon_aes_128_cbc(Config) when is_list(Config) ->
    run_ciphers_test(dh_anon, 'aes_128_cbc', Config).         

dh_anon_aes_128_gcm(Config) when is_list(Config) ->
    run_ciphers_test(dh_anon, 'aes_128_gcm', Config).         

dh_anon_aes_256_cbc(Config) when is_list(Config) ->
    run_ciphers_test(dh_anon, 'aes_256_cbc', Config).   

dh_anon_aes_256_gcm(Config) when is_list(Config) ->
    run_ciphers_test(dh_anon, 'aes_256_gcm', Config).   

dh_anon_rc4_128(Config) when is_list(Config) ->
    run_ciphers_test(dh_anon, 'rc4_128', Config).      

ecdh_anon_3des_ede_cbc(Config) when is_list(Config) ->
    run_ciphers_test(ecdh_anon, '3des_ede_cbc', Config).         

ecdh_anon_aes_128_cbc(Config) when is_list(Config) ->
    run_ciphers_test(ecdh_anon, 'aes_128_cbc', Config).   

ecdh_anon_aes_256_cbc(Config) when is_list(Config) ->
    run_ciphers_test(ecdh_anon, 'aes_256_cbc', Config).   

srp_anon_3des_ede_cbc(Config) when is_list(Config) ->
    run_ciphers_test(srp_anon, '3des_ede_cbc', Config).                 
    
srp_anon_aes_128_cbc(Config) when is_list(Config) ->
   run_ciphers_test(srp_anon, 'aes_128_cbc', Config).             

srp_anon_aes_256_cbc(Config) when is_list(Config) ->
   run_ciphers_test(srp_anon, 'aes_256_cbc', Config).     

dhe_psk_des_cbc(Config) when is_list(Config) ->
    run_ciphers_test(dhe_psk, 'des_cbc', Config).            

dhe_psk_rc4_128(Config) when is_list(Config) ->
    run_ciphers_test(dhe_psk, 'rc4_128', Config).            

dhe_psk_3des_ede_cbc(Config) when is_list(Config) ->
    run_ciphers_test(dhe_psk, '3des_ede_cbc', Config).            

dhe_psk_aes_128_cbc(Config) when is_list(Config) ->
    run_ciphers_test(dhe_psk, 'aes_128_cbc', Config).             

dhe_psk_aes_256_cbc(Config) when is_list(Config) ->
    run_ciphers_test(dhe_psk, 'aes_256_cbc', Config).

dhe_psk_aes_128_gcm(Config) when is_list(Config) ->
    run_ciphers_test(dhe_psk, 'aes_128_gcm', Config).             

dhe_psk_aes_256_gcm(Config) when is_list(Config) ->
    run_ciphers_test(dhe_psk, 'aes_256_gcm', Config).

dhe_psk_aes_128_ccm(Config) when is_list(Config) ->
    run_ciphers_test(dhe_psk, 'aes_128_ccm', Config).             

dhe_psk_aes_256_ccm(Config) when is_list(Config) ->
    run_ciphers_test(dhe_psk, 'aes_256_ccm', Config).

dhe_psk_aes_128_ccm_8(Config) when is_list(Config) ->
    run_ciphers_test(dhe_psk, 'aes_128_ccm_8', Config).

dhe_psk_aes_256_ccm_8(Config) when is_list(Config) ->
    run_ciphers_test(dhe_psk, 'aes_256_ccm_8', Config).

ecdhe_psk_des_cbc(Config) when is_list(Config) ->
    run_ciphers_test(ecdhe_psk, 'des_cbc', Config).            

ecdhe_psk_rc4_128(Config) when is_list(Config) ->
    run_ciphers_test(ecdhe_psk, 'rc4_128', Config).            

ecdhe_psk_3des_ede_cbc(Config) when is_list(Config) ->
    run_ciphers_test(ecdhe_psk, '3des_ede_cbc', Config).            

ecdhe_psk_aes_128_cbc(Config) when is_list(Config) ->
    run_ciphers_test(ecdhe_psk, 'aes_128_cbc', Config).             

ecdhe_psk_aes_256_cbc(Config) when is_list(Config) ->
    run_ciphers_test(ecdhe_psk, 'aes_256_cbc', Config).

ecdhe_psk_aes_128_gcm(Config) when is_list(Config) ->
    run_ciphers_test(ecdhe_psk, 'aes_128_gcm', Config).             

ecdhe_psk_aes_256_gcm(Config) when is_list(Config) ->
    run_ciphers_test(ecdhe_psk, 'aes_256_gcm', Config).

ecdhe_psk_aes_128_ccm(Config) when is_list(Config) ->
    run_ciphers_test(ecdhe_psk, 'aes_128_ccm', Config).             

ecdhe_psk_aes_128_ccm_8(Config) when is_list(Config) ->
    run_ciphers_test(ecdhe_psk, 'aes_128_ccm_8', Config).

psk_des_cbc(Config) when is_list(Config) ->
    run_ciphers_test(psk, 'des_cbc', Config).            

psk_rc4_128(Config) when is_list(Config) ->
    run_ciphers_test(psk, 'rc4_128', Config).            

psk_3des_ede_cbc(Config) when is_list(Config) ->
    run_ciphers_test(psk, '3des_ede_cbc', Config).            

psk_aes_128_cbc(Config) when is_list(Config) ->
    run_ciphers_test(psk, 'aes_128_cbc', Config).             

psk_aes_256_cbc(Config) when is_list(Config) ->
    run_ciphers_test(psk, 'aes_256_cbc', Config).

psk_aes_128_gcm(Config) when is_list(Config) ->
    run_ciphers_test(psk, 'aes_128_gcm', Config).             

psk_aes_256_gcm(Config) when is_list(Config) ->
    run_ciphers_test(psk, 'aes_256_gcm', Config).

psk_aes_128_ccm(Config) when is_list(Config) ->
    run_ciphers_test(psk, 'aes_128_ccm', Config).             

psk_aes_256_ccm(Config) when is_list(Config) ->
    run_ciphers_test(psk, 'aes_256_ccm', Config).

psk_aes_128_ccm_8(Config) when is_list(Config) ->
    run_ciphers_test(psk, 'aes_128_ccm_8', Config).             

psk_aes_256_ccm_8(Config) when is_list(Config) ->
    run_ciphers_test(psk, 'aes_256_ccm_8', Config).

%%--------------------------------------------------------------------
%% Internal functions  ----------------------------------------------
%%--------------------------------------------------------------------
test_cipher(TestCase, Config) ->
    ssl_cipher_suite_SUITE:test_cipher(TestCase, Config).

run_ciphers_test(Kex, Cipher, Config) ->
    Version = ssl_test_lib:protocol_version(Config),
    TestCiphers = test_ciphers(Kex, Cipher, Version),                  
    
    case TestCiphers of
        [_|_] -> 
            lists:foreach(fun(TestCipher) -> 
                                  cipher_suite_test(TestCipher, Version, Config)
                          end, TestCiphers);
        []  ->
            {skip, {not_sup, Kex, Cipher, Version}}
    end.

cipher_suite_test(CipherSuite, _Version, Config) ->
    #{server_config := SOpts,
      client_config := COpts} = proplists:get_value(tls_config, Config),
    ServerOpts = ssl_test_lib:ssl_options(SOpts, Config),
    ClientOpts = ssl_test_lib:ssl_options(COpts, Config),
    ct:log("Testing CipherSuite ~p~n", [CipherSuite]),
    ct:log("Server Opts ~p~n", [ServerOpts]),
    ct:log("Client Opts ~p~n", [ClientOpts]),
    ssl_test_lib:basic_test([{ciphers, [CipherSuite]} | COpts], SOpts, [{client_type, erlang},
                                                                        {server_type, openssl} | Config]).


test_ciphers(Kex, Cipher, Version) ->
    Ciphers = ssl:filter_cipher_suites(ssl:cipher_suites(default, Version) ++ ssl:cipher_suites(anonymous, Version), 
                             [{key_exchange, 
                               fun(Kex0) when Kex0 == Kex -> true; 
                                  (_) -> false 
                               end}, 
                              {cipher,  
                               fun(Cipher0) when Cipher0 == Cipher -> true; 
                                  (_) -> false 
                               end}]),
    ct:log("Version ~p Testing  ~p~n", [Version, Ciphers]),
    OpenSSLCiphers = openssl_ciphers(),
    ct:log("OpenSSLCiphers ~p~n", [OpenSSLCiphers]),
    lists:filter(fun(C) ->
                         ct:log("Cipher ~p~n", [C]),
                         lists:member(ssl_cipher_format:suite_map_to_openssl_str(C), OpenSSLCiphers)
                 end, Ciphers).


openssl_ciphers() ->
    Str = os:cmd("openssl ciphers"),
    string:split(string:strip(Str, right, $\n), ":", all).
