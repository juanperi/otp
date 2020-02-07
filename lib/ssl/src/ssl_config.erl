%%
%% %CopyrightBegin%
%%
%% Copyright Ericsson AB 2007-2018. All Rights Reserved.
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

-module(ssl_config).

-include("ssl_internal.hrl").
-include("ssl_connection.hrl").
-include_lib("public_key/include/public_key.hrl"). 

-export([init/2]).

init(#{erl_dist := ErlDist,
       dh := DH,
       dhfile := DHFile} = SslOpts, Role) ->
    
    init_manager_name(ErlDist),

    {ok, #{pem_cache := PemCache} = Config0} 
	= init_certificates(SslOpts, Role),
    {ok, Config}  = init_private_keys(SslOpts, Role, Config0),
        DHParams = init_diffie_hellman(PemCache, DH, DHFile, Role),
    {ok, Config#{dh_params => DHParams}}.

init_manager_name(false) ->
    put(ssl_manager, ssl_manager:name(normal)),
    put(ssl_pem_cache, ssl_pem_cache:name(normal));
init_manager_name(true) ->
    put(ssl_manager, ssl_manager:name(dist)),
    put(ssl_pem_cache, ssl_pem_cache:name(dist)).

init_certificates(#{cacerts := CaCerts,
                    cacertfile := CACertFile,
                    certfile := CertFile,
                    cert := Cert,
                    crl_cache := CRLCache
                   }, Role) ->
    {ok, Config} =
	try 
	    Certs = case CaCerts of
			undefined ->
			    CACertFile;
			_ ->
			    {der, CaCerts}
		    end,
	    {ok,_} = ssl_manager:connection_init(Certs, Role, CRLCache)
	catch
	    _:Reason ->
		file_error(CACertFile, {cacertfile, Reason})
	end,
    init_certificates(Cert, Config, CertFile, Role).

init_certificates(undefined, Config, <<>>, _) ->
    {ok, Config#{own_certificates => undefined}};

init_certificates(undefined, #{pem_cache := PemCache} = Config, CertFile, client) ->
    try 
	%% Ignoring potential proxy-certificates see: 
	%% http://dev.globus.org/wiki/Security/ProxyFileFormat
	[OwnCert|_] = ssl_certificate:file_to_certificats(CertFile, PemCache),
	{ok, Config#{own_certificates => [OwnCert]}}
    catch _Error:_Reason  ->
	    {ok, Config#{own_certificates => undefined}}
    end; 

init_certificates(undefined, #{pem_cache := PemCache} = Config, CertFile, server) ->
    try
	[OwnCert|_] = ssl_certificate:file_to_certificats(CertFile, PemCache),
	{ok, Config#{own_certificates => [OwnCert]}}
    catch
	_:Reason ->
	    file_error(CertFile, {certfile, Reason})	    
    end;
init_certificates(Cert, Config, _, _) ->
    {ok, Config#{own_certificates => [Cert]}}.

init_private_key(_, #{algorithm := Alg} = Key, _, _Password, _Client) when Alg == ecdsa;
                                                                           Alg == rsa;
                                                                           Alg == dss ->
    case maps:is_key(engine, Key) andalso maps:is_key(key_id, Key) of
        true ->
            Key;
        false ->
            throw({key, {invalid_key_id, Key}})
    end;
init_private_key(_, undefined, <<>>, _Password, _Client) ->
    undefined;
init_private_key(DbHandle, undefined, KeyFile, Password, _) ->
    try
	{ok, List} = ssl_manager:cache_pem_file(KeyFile, DbHandle),
	[PemEntry] = [PemEntry || PemEntry = {PKey, _ , _} <- List,
				  PKey =:= 'RSAPrivateKey' orelse
				      PKey =:= 'DSAPrivateKey' orelse
				      PKey =:= 'ECPrivateKey' orelse
				      PKey =:= 'PrivateKeyInfo'
		     ],
	private_key(public_key:pem_entry_decode(PemEntry, Password))
    catch 
	_:Reason ->
	    file_error(KeyFile, {keyfile, Reason}) 
    end;

init_private_key(_,{Asn1Type, PrivateKey},_,_,_) ->
    private_key(init_private_key(Asn1Type, PrivateKey)).

init_private_key(Asn1Type, PrivateKey) ->
    public_key:der_decode(Asn1Type, PrivateKey).

private_key(#'PrivateKeyInfo'{privateKeyAlgorithm =
				 #'PrivateKeyInfo_privateKeyAlgorithm'{algorithm = ?'rsaEncryption'},
			     privateKey = Key}) ->
    public_key:der_decode('RSAPrivateKey', iolist_to_binary(Key));

private_key(#'PrivateKeyInfo'{privateKeyAlgorithm =
				 #'PrivateKeyInfo_privateKeyAlgorithm'{algorithm = ?'id-dsa'},
			     privateKey = Key}) ->
    public_key:der_decode('DSAPrivateKey', iolist_to_binary(Key));
private_key(#'PrivateKeyInfo'{privateKeyAlgorithm = 
                                  #'PrivateKeyInfo_privateKeyAlgorithm'{algorithm = ?'id-ecPublicKey',
                                                                        parameters =  {asn1_OPENTYPE, Parameters}},
                              privateKey = Key}) ->
    ECKey = public_key:der_decode('ECPrivateKey',  iolist_to_binary(Key)),
    ECParameters = public_key:der_decode('EcpkParameters', Parameters),
    ECKey#'ECPrivateKey'{parameters = ECParameters};
private_key(Key) ->
    Key.

-spec(file_error(_,_) -> no_return()).
file_error(File, Throw) ->
    case Throw of
	{Opt,{badmatch, {error, {badmatch, Error}}}} ->
	    throw({options, {Opt, binary_to_list(File), Error}});
	{Opt, {badmatch, Error}} ->
	    throw({options, {Opt, binary_to_list(File), Error}});
	_ ->
	    throw(Throw)
    end.

init_diffie_hellman(_,Params, _,_) when is_binary(Params)->
    public_key:der_decode('DHParameter', Params);
init_diffie_hellman(_,_,_, client) ->
    undefined;
init_diffie_hellman(_,_,undefined, _) ->
    ?DEFAULT_DIFFIE_HELLMAN_PARAMS;
init_diffie_hellman(DbHandle,_, DHParamFile, server) ->
    try
	{ok, List} = ssl_manager:cache_pem_file(DHParamFile,DbHandle),
	case [Entry || Entry = {'DHParameter', _ , _} <- List] of
	    [Entry] ->
		public_key:pem_entry_decode(Entry);
	    [] ->
		?DEFAULT_DIFFIE_HELLMAN_PARAMS
	end
    catch
	_:Reason ->
	    file_error(DHParamFile, {dhfile, Reason}) 
    end.


init_private_keys(#{key := Key,
                    keyfile := KeyFile,
                    password := Password}, Role,
                  #{pem_cache := PemCache,
                   own_certificates := Certs} = Config) -> 
    PrivKey = init_private_key(PemCache, Key, KeyFile, Password, Role),
    PrivKeys = maybe_map_cert_keys(PrivKey, Certs),
    {ok, Config#{private_keys => PrivKeys}}.
    
maybe_map_cert_keys(undefined, _) ->
    undefined;
maybe_map_cert_keys(Key, [Cert]) ->
    map_cert_keys([{Cert, Key}]).

map_cert_keys(CertKeys) ->
    map_cert_keys(CertKeys, #{}).

map_cert_keys([], Acc) ->
    Acc;
map_cert_keys([{Cert, {Type, Key}} | Rest], Acc) ->
    PrivKey = init_private_key(Type, Key),
    {ok, Id} = public_key:pkix_issuer_id(Cert, self),
    map_cert_keys(Rest, Acc#{Id => PrivKey});
map_cert_keys([{Cert, Key} | Rest], Acc) ->
    {ok, Id} = public_key:pkix_issuer_id(Cert, self),
    map_cert_keys(Rest, Acc#{Id => Key}).

%% If multiple cert and keys are inputed via a PEM file they are
%% hopefully provided in the same order but PEM files do have a given
%% order so we have to make sure we have a orderd list.
sort_cert_keys([], [], _, _, Acc) ->
    Acc;
sort_cert_keys([_|_], [], [], Opt, _) ->
    throw({options, {{certs_and_kyes, Opt}, key_cert_mismatch}});
sort_cert_keys([_|_]= Certs, [], UnUsedKeys = [_|_], Opt, Acc) ->
    case length(Certs) == length(UnUsedKeys) of
        true ->
            throw({options, {{certs_and_kyes, Opt}, key_cert_mismatch}});
        false ->
            sort_cert_keys(Certs, UnUsedKeys, [], Opt, Acc)
    end;
sort_cert_keys([Cert | Certs], [Key | Keys], UnUsedKeys, Opt, Acc) ->
    case is_cert_key(Cert, Key) of
        true ->
            sort_cert_keys(Certs,  Keys,  UnUsedKeys, Opt, [{Cert, Key} | Acc]);
        false  ->
            sort_cert_keys([Cert | Certs], Keys, [Key| UnUsedKeys], Opt,  Acc)
    end.

is_cert_key(_Cert, _Key) ->
    ture.
