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
%%----------------------------------------------------------------------
%% Purpose: Handles TLS session ticket introduced in TLS-1.3
%%----------------------------------------------------------------------

-module(tls_session_ticket).

-include("tls_handshake_1_3.hrl").

-export([get_ticket_data/2, 
         %% seed/0,
         %% increment_seed/1
         %%store_server_state/1, 
         %%read_server_state/0, 
         %%increment_ticket_nonce/0,
         store_session_ticket/4]).


%% seed() ->
%%     #{nonce => 0,
%%       ticket_iv => crypto:strong_rand_bytes(16),
%%       ticket_key_shard => crypto:strong_rand_bytes(32)
%%      }.

%% increment_seed(#{nonce := Nonce} = Seed) ->
%%     Seed#{nonce => Nonce + 1}.


%% store_server_state(#ticket_seed{
%%                       nonce = Nonce,
%%                       ticket_iv = IV,
%%                       ticket_key_shard = Key}) ->
%%     case ets:whereis(tls13_server_state) of
%%         undefined ->
%%             ets:new(tls13_server_state, [public, named_table, ordered_set]);
%%         Tid ->
%%             Tid
%%     end,
%%     ServerId = 1,
%%     ets:insert(tls13_server_state, {ServerId, Nonce, IV, Key}).


%% read_server_state() ->
%%     case ets:lookup(tls13_server_state, 1) of
%%         [{_Id, Nonce, IV, Key}] ->
%%             #ticket_seed{
%%                nonce = Nonce,
%%                ticket_iv = IV,
%%                ticket_key_shard = Key
%%               };
%%         [] ->
%%             %% TODO Fault handling
%%             undefined
%%     end.


%% increment_ticket_nonce() ->
%%     ets:update_counter(tls13_server_state, 1, 1).


store_session_ticket(NewSessionTicket, HKDF, SNI, PSK) ->
    _TicketDb =
        case ets:whereis(tls13_session_ticket_db) of
            undefined ->
                ets:new(tls13_session_ticket_db, [public, named_table, ordered_set]);
            Tid ->
                Tid
        end,
    Id = make_ticket_id(NewSessionTicket),
    Timestamp = gregorian_seconds(),
    ets:insert(tls13_session_ticket_db, {Id, HKDF, SNI, PSK, Timestamp, NewSessionTicket}).


make_ticket_id(NewSessionTicket) ->
    {_, B} = tls_handshake_1_3:encode_handshake(NewSessionTicket),
    crypto:hash(sha256, B).


get_ticket_data(undefined, _) ->
    undefined;
get_ticket_data(_, undefined) ->
    undefined;
get_ticket_data(_, UseTicket) ->
    case ets:lookup(tls13_session_ticket_db, UseTicket) of
        [{_Key, HKDF, _SNI, PSK, Timestamp, NewSessionTicket}] ->
            #new_session_ticket{
               ticket_lifetime = _LifeTime,
               ticket_age_add = AgeAdd,
               ticket_nonce = Nonce,
               ticket = Ticket,
               extensions = _Extensions
              } = NewSessionTicket,

            TicketAge = gregorian_seconds() - Timestamp,
            ObfuscatedTicketAge = obfuscate_ticket_age(TicketAge, AgeAdd),
            Identities = [#psk_identity{
                             identity = Ticket,
                             obfuscated_ticket_age = ObfuscatedTicketAge}],

            {Identities, PSK, Nonce, HKDF};
        [] ->
            %% TODO Fault handling
            undefined
    end.

%%--------------------------------------------------------------------
%%% Internal functions
%%--------------------------------------------------------------------
%% The "obfuscated_ticket_age"
%% field of each PskIdentity contains an obfuscated version of the
%% ticket age formed by taking the age in milliseconds and adding the
%% "ticket_age_add" value that was included with the ticket
%% (see Section 4.6.1), modulo 2^32.
obfuscate_ticket_age(TicketAge, AgeAdd) ->
    (TicketAge * 1000 + AgeAdd) rem round(math:pow(2,32)).


gregorian_seconds() ->
    calendar:datetime_to_gregorian_seconds(calendar:now_to_datetime(erlang:timestamp())).
