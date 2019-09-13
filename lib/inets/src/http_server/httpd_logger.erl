%%
%% %CopyrightBegin%
%%
%% Copyright Ericsson AB 1997-2017. All Rights Reserved.
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
-module(httpd_logger).

-include_lib("kernel/include/logger.hrl").
-include_lib("inets/include/httpd.hrl").

-export([error_report/3, error_report/4, error_report/5, log/2, format/1, legacy_format/1]). 


error_report(http, Format, Args, Mod) ->
    Report = error_report(http, "", Mod),
    Report#{format => Format,
            args => Args};
error_report(internal, Format, Args, Mod) ->
    Report = error_report(internal, "", Mod),
    Report#{format => Format,
            args => Args}.

error_report(http, Prefix, Format, Args, Mod) ->
    Report = error_report(http, Prefix, Mod),
    Report#{format => Format,
            args => Args}.

error_report(Protocol, Desc, #mod{init_data = #init_data{peername = {PeerPort, PeerIP}, sockname = {Port, IP}}} = Mod) ->
    #{protocol => Protocol,
      error_desc => Desc,
      peer => PeerIP ++ ":" ++ erlang:integer_to_list(PeerPort),
      host => IP ++ ":" ++ erlang:integer_to_list(Port),
      mod => Mod,
      level => error}.

log(#{level := error} = Report, Domain) ->
    ?LOG_ERROR(Report, #{domain => [otp,inets, httpd, Domain],
                         report_cb => fun ?MODULE:format/1}).

format(#{protocol := tls} = Report) -> 
    #{err_desc := AlertDesc,
      peer := Peer,
      host := Host,
      mod := #mod{config_db = Db}} = Report,
    ServerName = httpd_util:lookup(Db, server_name),
    {"-- HTTP server ~p -- failed TLS connection between Host: ~p~n "
     "and client ~p due to ~s~n", 
     [ServerName, Host, Peer, AlertDesc]};
format(#{protocol := tcp} = Report) -> 
    #{error_desc := Desc,
      peer := Peer,
      host := Host,
      mod := #mod{config_db = Db}} = Report,
    ServerName = httpd_util:lookup(Db, server_name),
    {"-- HTTP server ~s -- failed TCP connection between Host: ~p~n "
     "and client ~p due to ~s~n", 
     [ServerName, Host, Peer, Desc]};
format(#{protocol := http} = Report) -> 
    #{error_desc := Prefix,
      format := Format,
      args := Args,
      host := Host,
      peer := Peer,
      mod := #mod{config_db = Db}} = Report,
    ServerName = httpd_util:lookup(Db, server_name),
    case Prefix of
        "" ->            
            {"-- HTTP server ~s (~p): Sent error to ~p" ++ Format, [ServerName, Host, Peer | Args]};
        _ ->
            {"-- HTTP server ~s (~p): Sent error to ~p ~s" ++ Format, [ServerName, Host, Peer, Prefix | Args]}
    end;
format(#{protocol := internal} = Report) -> 
    #{format := Format,
      args := Args,
      host := Host,
      mod := #mod{config_db = Db}
     } = Report,
    ServerName = httpd_util:lookup(Db, server_name),
    {"-- HTTP server ~s (~p):" ++ Format, [ServerName, Host |Args]};
format(ErrStr) when is_list(ErrStr) -> 
    legacy_format(ErrStr).

legacy_format(#{protocol := http} = Report) ->
    #{error_desc := Prefix,
      format := Format,
      args := Args} = Report,
    case Prefix of
        "" ->            
            {Format, Args};
        _ ->
            {Format, [Prefix | Args]}
    end;
legacy_format(#{protocol := tcp} = Report) -> 
    #{error_desc := Desc} = Report,
    {Desc,[]};
legacy_format(#{protocol := _} = Report) ->
    format(Report);
legacy_format(ErrStr) when is_list(ErrStr)->
    {ErrStr, []}.
