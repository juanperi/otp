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

%%----------------------------------------------------------------------
%% Purpose: Handle server side TLS-1.3 session ticket storage 
%%----------------------------------------------------------------------

-module(tls_server_session_ticket).
-behaviour(gen_server).

-include("tls_handshake_1_3.hrl").
-include("ssl_internal.hrl").

%% API
-export([start_link/2, new/1]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
         terminate/2, code_change/3, format_status/2]).

-define(SERVER, ?MODULE).

-record(state, {
                stateless_nonce,
                lifetime 
               }).

%%%===================================================================
%%% API
%%%===================================================================
-spec start_link(atom(), integer()) -> {ok, Pid :: pid()} |
                      {error, Error :: {already_started, pid()}} |
                      {error, Error :: term()} |
                      ignore.
start_link(Mode, Lifetime) ->
    gen_server:start_link(?MODULE, [Mode, Lifetime], []).


new(Pid) ->
    gen_server:call(Pid, new_ticket, infinity).

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================

-spec init(Args :: term()) -> {ok, State :: term()}.                             

init(Args) ->
    process_flag(trap_exit, true),
    inital_state(Args),
    {ok, #state{}}.

-spec handle_call(Request :: term(), From :: {pid(), term()}, State :: term()) ->
                         {reply, Reply :: term(), NewState :: term()} |
                         {reply, Reply :: term(), NewState :: term(), Timeout :: timeout()} |
                         {reply, Reply :: term(), NewState :: term(), hibernate} |
                         {noreply, NewState :: term()} |
                         {noreply, NewState :: term(), Timeout :: timeout()} |
                         {noreply, NewState :: term(), hibernate} |
                         {stop, Reason :: term(), Reply :: term(), NewState :: term()} |
                         {stop, Reason :: term(), NewState :: term()}.
handle_call(new_ticket, _From, #state{stateless_nonce = Nonce} = State) when Nonce =:= undefined -> 
    TicketAgeAdd = ticket_age_add(),
    Reply = #new_session_ticket{
               ticket_lifetime = State#state.lifetime,
               ticket_age_add = TicketAgeAdd,
               ticket_nonce = ticket_nonce(Nonce),
               extensions = #{}
              }, 
    {reply, Reply, State#state{stateless_nonce = Nonce + 1}}.

-spec handle_cast(Request :: term(), State :: term()) ->
                         {noreply, NewState :: term()} |
                         {noreply, NewState :: term(), Timeout :: timeout()} |
                         {noreply, NewState :: term(), hibernate} |
                         {stop, Reason :: term(), NewState :: term()}.
handle_cast(_Request, State) ->
    {noreply, State}.

-spec handle_info(Info :: timeout() | term(), State :: term()) ->
                         {noreply, NewState :: term()} |
                         {noreply, NewState :: term(), Timeout :: timeout()} |
                         {noreply, NewState :: term(), hibernate} |
                         {stop, Reason :: normal | term(), NewState :: term()}.
handle_info(_Info, State) ->
    {noreply, State}.


-spec terminate(Reason :: normal | shutdown | {shutdown, term()} | term(),
                State :: term()) -> any().
terminate(_Reason, _State) ->
    ok.

-spec code_change(OldVsn :: term() | {down, term()},
                  State :: term(),
                  Extra :: term()) -> {ok, NewState :: term()} |
                                      {error, Reason :: term()}.
code_change(_OldVsn, State, _Extra) ->
    {ok, State}.


-spec format_status(Opt :: normal | terminate,
                    Status :: list()) -> Status :: term().
format_status(_Opt, Status) ->
    Status.
%%%===================================================================
%%% Internal functions
%%%===================================================================

inital_state([stateless, Lifetime]) ->
    #state{stateless_nonce = 0,
           lifetime = Lifetime
          };
inital_state([statefull, Lifetime]) ->
    #state{lifetime = Lifetime
          }.

ticket_age_add() ->
    <<?UINT32(I)>> = crypto:strong_rand_bytes(4),
    I.

ticket_nonce(I) ->
    <<?UINT64(I)>>.

