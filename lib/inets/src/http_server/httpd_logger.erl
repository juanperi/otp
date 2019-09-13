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

-export([report/3, error_log/2, format/2]). 

report(tcp, Desc, #mod{init_data = #init_data{peername = Peer, sockname = Host}}) ->
    #{protocol => tcp,
      error_desc => Desc,
      peer => Peer,
      host => Host}; 
report(tls, Desc, #mod{init_data = #init_data{peername = Peer, sockname = Host}}) ->
    #{protocol => tls,
      alert_desc => Desc,
      peer => Peer,
      host => Host}; 
report(http, Desc, ModData) ->
    #{error_desc => Desc,
      mod => ModData}.

error_log(Report, Domain) ->
    ?LOG_DEBUG(Report, #{domain => [otp,inets, httpd, Domain]}).

format(#{msg:= {report, #{protocol = tls} = Report}}, _Config) -> 
    #{alert_desc := AlertDesc,
      peer := Peer,
      host := Host} = Report,
    Data = io_lib:format("TLS connection failed between Host: ~p~n "
                         "and Peer ~p due to  ~p~n", 
                         [Host, Peer, AlertDesc]),
    unicode:characters_to_binary(Data);
format(#{msg:= {report, #{protocol = tcp} = Report}}, _Config) -> 
    #{error_desc = Desc,
      peer := Peer,
      host := Host} = Report,
    Data = io_lib:format("TLS connection failed between Host: ~p~n "
                         "and Peer ~p due to  ~p~n", 
                         [Host, Peer, AlertDesc]),
    unicode:characters_to_binary(Data);

format(#{msg:= {report, #{protocol = http} = Report}}, _Config) -> 
    #{error_desc := ErrDescription,
      mod := #mod{} = ModData} = Report,
    Data = httpd_log:error_entry(ModData, Reason),
    unicode:characters_to_binary(Data);
format(Str, _) when is_list(Str)->  %% Backwards compat 
    unicode:characters_to_binary(Str).
