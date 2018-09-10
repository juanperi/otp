%%
%% %CopyrightBegin%
%%
%% Copyright Ericsson AB 2008-2016. All Rights Reserved.
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

-module(ssl_session_cache_api).
-include("ssl_handshake.hrl").
-include("ssl_internal.hrl").
-include("ssl_api.hrl").

-export_type([session_cache_key/0, session/0, partial_key/0, session_cache_ref/0]).

-type session_cache_ref() :: cache_handle().
-type session_cache_key() :: {partial_key(), ssl:session_id()}.
-opaque session()         :: #session{}.
-opaque partial_key()     :: {ssl:host(), inet:port_number()} | inet:port_number().
-type cache_handle()         :: term().

-callback init(list()) -> cache_handle().
-callback terminate(cache_handle()) -> any().
-callback lookup(cache_handle(), session_cache_key()) -> #session{} | undefined.
-callback update(cache_handle(), session_cache_key(), #session{}) -> any().
-callback delete(cache_handle(), session_cache_key()) -> any().
-callback foldl(fun(), term(), cache_handle()) -> term().
-callback select_session(cache_handle(), {ssl:host(), inet:port_number()} | inet:port_number()) -> [#session{}].
-callback size(cache_handle()) -> integer().
