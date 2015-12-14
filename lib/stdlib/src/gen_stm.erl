%%
%% %CopyrightBegin%
%%
%% Copyright Ericsson AB 2015. All Rights Reserved.
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
-module(gen_stm).

%% API
-export(
   [start/3,start/4,start_link/3,start_link/4,
    stop/1,stop/3,
    send/2,event/2,call/2,
    enter_loop/4,enter_loop/5,enter_loop/6,
    reply/2]).

%% gen callbacks
-export(
   [init_it/6]).

%% sys callbacks
-export(
   [system_continue/3,
    system_terminate/4,
    system_code_change/4,
    system_get_state/1,
    system_replace_state/2,
    format_status/2]).

%% Internal callbacks
-export(
   [wakeup_from_hibernate/3]).

%%%==========================================================================
%%% Interface functions.
%%%==========================================================================

-type from() :: {To :: pid(), Tag :: term()}.
-type state() :: atom().
-type state_data() :: term().
-type event_type() ::
	{call,from()} | event | info | % Used in this version
	tuple() | atom() | % Reserved for future use
	term(). % Free to use for implementation internal events
-type event_content() :: term().
-type remove_event_predicate() :: % Return true for event to remove
	fun((event_type(), event_content()) -> boolean()).
-type reason() :: term().
-type state_op() ::
	%% First NewState and NewState data and postponing
	%% the current event (iff 'retry' is present in [state_op()])
	%% is executed, then all state_op() in order of apperance,
	%% and lastly, if hibernate was present in [state_op()]
	%% the server is hibernated instead of starting to
	%% process events
	retry | % Postpone the current event to an other state
	hibernate |
	{stop, reason()} |
	{insert_event, % Insert the event as the oldest i.e next to handle
	 event_type(), event_content()} |
	{remove_event, % Remove the oldest matching event
	 event_type(), event_content()} |
	{remove_event, % Remove the oldest event satisfying predicate
	 remove_event_predicate()} |
	{cancel_timer, % Cancel timer and clean up mess(ages)
	 TimerRef :: reference()} |
	{demonitor, % Demonitor and clean up mess(ages)
	 MonitorRef :: reference()} |
	{unlink, % Unlink and clean up mess(ages)
	 Id :: pid() | port()}.
-type process_dictionary() :: [{Key :: term(), Value :: term()}].

%% This is not a state callback.  It is called only once and
%% the server is not running until this function has returned
%% an {ok, ...} tuple.  Thereafter the state callbacks are called
%% for all events (messages) to this server.
-callback init(Args :: term()) ->
    {ok, state(), state_data()} |
    {ok, state(), state_data(), [state_op()]} |
    ignore |
    {stop, reason()}.

%% An example callback for state 'init'.
%% Note that state callbacks and only state callbacks have arity 5
%% and that is intended to be a guarantee.
-callback init(
	    event_type(),
	    event_content(),
	    PrevState :: state(),
	    State :: state(), % Current state; 'init' in this example
	    StateData :: state_data()) ->
    [state_op()] | % {State,StateData,[state_op()]}
    {} | % {State,StateData,[]}
    {NewStateData :: state_data()} | % {State,NewStateData,[retry]}
    {NewState :: state(),
     NewStateData :: state_data()} | % {NewState,NewStateData,[]}
    {NewState :: state(), NewStateData :: state_data(), [state_op()]}.

%% -callback handle_event(
%% 	    Event :: event(), State :: term(), StateData :: term()) ->
%%     {event_action(), NewState :: term(), NewData :: term()} |
%%     {event_action(), NewState :: term(), NewData :: term(),
%%      [event_option()]} |
%%     {stop, reason(), NewData :: term()}.

%% Clean up before the server terminates.
-callback terminate(
	    Reason :: normal | shutdown | {shutdown, term()} | reason(),
	    State :: state(),
	    StateData :: state_data()) ->
    any().

%% Note that the new code has to be prepared for an OldState
%% from the old code version in all state functions.
-callback code_change(
	    OldVsn :: term() | {down, term()},
	    OldState :: state(),
	    OldStateData :: state_data(),
	    Extra :: term()) ->
    {ok, State :: state(), StateData :: state_data()} |
    {ok, State :: state(), StateData :: state_data(), [state_op()]}.

-callback format_status(
	    StatusOption,
	    [process_dictionary() |
	     state() |
	     state_data()]) ->
    Status :: term() when
      StatusOption :: normal | terminate.

-optional_callbacks(
   [format_status/2,
    init/5]).


%%%==========================================================================
%%% API

%% Start a state machine
start(Mod, Args, Options) ->
    gen:start(?MODULE, nolink, Mod, Args, Options).
%%
start(Server, Mod, Args, Options) ->
    gen:start(?MODULE, nolink, Server, Mod, Args, Options).

%% Start and link to a state machine
start_link(Mod, Args, Options) ->
    gen:start(?MODULE, link, Mod, Args, Options).
%%
start_link(Server, Mod, Args, Options) ->
    gen:start(?MODULE, link, Server, Mod, Args, Options).

%% Stop a state machine
stop(Server) ->
    gen:stop(Server).
%%
stop(Server, Reason, Timeout) ->
    gen:stop(Server, Reason, Timeout).

%% Send an message to a state machine i.e the same as Server ! Msg
%% but Server can be like first argument to event/2 and call/2.
send({global,Name}, Msg) ->
    try	global:send(Name, Msg) of
	_ -> ok
    catch
	_:_ -> ok
    end;
send({via,Mod,Name}, Msg) ->
    try	Mod:send(Name, Msg) of
	_ -> ok
    catch
	_:_ -> ok
    end;
send({Name,Node} = Server, Msg) when is_atom(Name), is_atom(Node) ->
    do_send(Server, Msg);
send(Server, Msg) when is_atom(Server) ->
    do_send(Server, Msg);
send(Server, Msg) when is_pid(Server) ->
    do_send(Server, Msg).

%% Send an event to a state machine that arrives with type 'info'
event(Server, Event) ->
    send(Server, event_msg(Event)).

%% Call a state machine (synchronous; a reply is expected) that
%% arrives with type {call,From}
call(Server, Request) ->
    try gen:call(Server, '$gen_call', Request) of
	{ok,Reply} ->
	    Reply
    catch
	Class:Reason ->
	    erlang:raise(
	      Class,
	      {Reason,{?MODULE,call,[Server,Request]}},
	      erlang:get_stacktrace())
    end.

%% Reply from a state machine callback to whom awaits in call/2
%% XXX Should we remove this since it does not produce debug output?
reply({To,Tag}, Reply) ->
    Msg = {Tag,Reply},
    try To ! Msg of
	_ ->
	    ok
    catch
	_:_ -> ok
    end.

%% Instead of starting the state machine through start/3,4
%% or start_link/3,4 turn the current process presumably
%% started by proc_lib into a state machine using
%% the same arguments as you would have returned from init/1
enter_loop(Module, Options, State, StateData) ->
    enter_loop(Module, Options, State, StateData, self()).
%%
enter_loop(Module, Options, State, StateData, Server) ->
    enter_loop(Module, Options, State, StateData, Server, []).
%%
enter_loop(Module, Options, State, StateData, Server, StateOps) ->
    Parent = gen:get_parent(),
    enter(Module, Options, State, StateData, Server, StateOps, Parent).

%%---------------------------------------------------------------------------
%% API helpers

event_msg(Event) ->
    {'$gen_event',Event}.

%% Might actually not send the message
do_send(Server, Msg) ->
    try erlang:send(Server, Msg, [noconnect]) of
	noconnect ->
	    spawn(erlang, send, [Server,Msg]),
	    ok;
	ok ->
	    ok
    catch
	_:_ ->
	    ok
    end.

enter(Module, Options, State, StateData, Server, StateOps, Parent) ->
    Name = gen:get_proc_name(Server),
    Debug = gen:debug_options(Name, Options),
    S = #{
      module => Module,
      name => Name,
      prev_state => '',
      state => State,
      state_data => StateData,
      queue => [],
      postponed => [],
      hibernate => false},
    loop_state_ops(Parent, Debug, S, StateOps).

%%%==========================================================================
%%%  gen callbacks

init_it(Starter, Parent, Server, Module, Args, Options) ->
    try Module:init(Args) of
	Result ->
	    init_result(Starter, Parent, Server, Module, Result, Options)
    catch
	Result ->
	    init_result(Starter, Parent, Server, Module, Result, Options);
	Class:Reason ->
	    gen:unregister_name(Server),
	    proc_lib:init_ack(Starter, {error,Reason}),
	    erlang:raise(Class, Reason, erlang:get_stacktrace())
    end.

%%---------------------------------------------------------------------------
%% gen callbacks helpers

init_result(Starter, Parent, Server, Module, Result, Options) ->
    case Result of
	{ok,State,StateData} ->
	    proc_lib:init_ack(Starter, {ok,self()}),
	    enter(Module, Options, State, StateData, Server, [], Parent);
	{ok,State,StateData,StateOps} ->
	    proc_lib:init_ack(Starter, {ok,self()}),
	    enter(Module, Options, State, StateData, Server, StateOps, Parent);
	{stop,Reason} ->
	    gen:unregister_name(Server),
	    proc_lib:init_ack(Starter, {error,Reason}),
	    exit(Reason);
	ignore ->
	    gen:unregister_name(Server),
	    proc_lib:init_ack(Starter, ignore),
	    exit(normal);
	Other ->
	    Error = {bad_return_value,Other},
	    proc_lib:init_ack(Starter, {error,Error}),
	    exit(Error)
    end.

%%%==========================================================================
%%% sys callbacks

system_continue(Parent, Debug, S) ->
    loop(Parent, Debug, S).

system_terminate(Reason, _Parent, Debug, S) ->
    terminate(Reason, Debug, S).

system_code_change(
  #{module := Module,
    state := State,
    state_data := StateData} = S,
  _Mod, OldVsn, Extra) ->
    case
	try Module:code_change(OldVsn, State, StateData, Extra)
	catch
	    Result -> Result
	end
    of
	{ok,NewState,NewStateData} ->
	    {ok,
	     S#{
	       state := NewState,
	       state_data := NewStateData}};
	BadResult ->
	    {bad_return_value,BadResult}
    end.

%% The state we show to sys tools is a 2-tuple, not a pair
%% to not scare people
system_get_state(#{state := State, state_data := StateData}) ->
    {ok,{State,StateData}}.

system_replace_state(
  StateFun,
  #{state := State,
    state_data := StateData} = S) ->
    {NewState,NewStateData} = Result = StateFun({State,StateData}),
    {ok,Result,S#{state := NewState, state_data := NewStateData}}.

format_status(
  Opt,
  [PDict,SysState,Parent,Debug,
   #{name := Name, queue := Q, postponed := P} = S]) ->
    Header = gen:format_status_header("Status for state machine", Name),
    Log = sys:get_debug(log, Debug, []),
    [{header,Header},
     {data,
      [{"Status",SysState},
       {"Parent",Parent},
       {"Logged Events",Log},
       {"Queue",Q},
       {"Postponed",P}]} |
     case format_status(Opt, PDict, S) of
	 L when is_list(L) -> L;
	 T -> [T]
     end].

%%---------------------------------------------------------------------------
%% Format debug messages.  Print them as the call-back module sees
%% them, not as the real erlang messages.  Use trace for that.
%%---------------------------------------------------------------------------

print_event(Dev, {in,Event}, {Name,_State}) ->
    io:format(
      Dev, "*DBG* ~p received ~s~n",
      [Name,event_string(Event)]);
print_event(Dev, {out,Reply,{To,_Tag}}, {Name,_State}) ->
    io:format(
      Dev, "*DBG* ~p sent ~p to ~p~n",
      [Name,Reply,To]);
print_event(Dev, {Tag,Event,NewState}, {Name,State}) ->
    StateString =
	case NewState of
	    State ->
		io_lib:format("~p", [State]);
	    _ ->
		io_lib:format("~p => ~p", [State,NewState])
	end,
    io:format(
      Dev, "*DBG* ~p ~w ~s in state ~s~n",
      [Name,Tag,event_string(Event),StateString]).

event_string(Event) ->
    case Event of
	{call,{{From,_Tag},Request}} ->
	    io_lib:format("call ~p from ~w", [Request,From]);
	{Tag,Content} ->
	    io_lib:format("~w ~p", [Tag,Content])
    end.


%%%==========================================================================
%%% Internal callbacks

wakeup_from_hibernate(Parent, Debug, S) ->
    %% It is a new message that woke us up so we have to receive it now
    loop_receive(Parent, Debug, S).

%%%==========================================================================
%%% STate Machine engine implementation of proc_lib/gen server

%%  Server loop

%% Entry point for system_continue/3
loop(Parent, Debug, #{hibernate := Hib} = S) ->
    case Hib of
	true ->
	    loop_hibernate(Parent, Debug, S);
	false ->
	    %% Process queued events before receiving new
	    loop_event(Parent, Debug, S)
    end.

loop_hibernate(Parent, Debug, S) ->
    %% Does not return but restarts process at
    %% wakeup_from_hibernate/3 that jumps to loop_receive/3
    proc_lib:hibernate(
      ?MODULE, wakeup_from_hibernate, [Parent,Debug,S]),
    error(
      {should_not_have_arrived_here_but_instead_in,
       {wakeup_from_hibernate,3}}).

%% Entry point for wakeup_from_hibernate/3
loop_receive(
  Parent, Debug,
  #{name := Name, state := State, hibernate := Hib} = S) ->
    receive
	Msg ->
	    case Msg of
		{system,From,Req} ->
		    %% Does not return but tail recursively calls
		    %% system_continue/3 that jumps to loop/3
		    sys:handle_system_msg(
		      Req, From, Parent, ?MODULE, Debug, S, Hib);
		{'EXIT',Parent,Reason} ->
		    terminate(Reason, Debug, S);
		_ ->
		    %% Put event last in queue.
		    %% We received a non-system message so
		    %% this is the end of hibernation.
		    #{queue := Q} = S,
		    Event = event(Msg),
		    NewDebug =
			case Debug of
			    [] ->
				Debug;
			    _ ->
				sys:handle_debug(
				  Debug, fun print_event/3,
				  {Name,State}, {in,Event})
			end,
		    loop_event(
		      Parent, NewDebug,
		      S#{queue := Q ++ [Event], hibernate := false})
	    end
    end.

%% Process first event in queue, or if there is none receive a new
loop_event(Parent, Debug, #{queue := []} = S) ->
    loop_receive(Parent, Debug, S);
loop_event(
  Parent, Debug,
  #{module := Module,
    prev_state := PrevState,
    state := State,
    state_data := StateData,
    queue := [{Type,Content} = Event|_]} = S) ->
    try Module:State(Type, Content, PrevState, State, StateData) of
	Result ->
	    loop_event_result(Parent, Debug, S, Result)
    catch
	Result ->
	    loop_event_result(Parent, Debug, S, Result);
	error:undef ->
	    %% Process an undef to check for the simple mistake
	    %% of calling a nonexistent state function
	    case erlang:get_stacktrace() of
		[{Module,State,[Event,StateData]=Args,_}|Stacktrace] ->
		    terminate(
		      error,
		      {undef_state_function,{Module,State,Args}},
		      Stacktrace,
		      Debug, S);
		Stacktrace ->
		    terminate(error, undef, Stacktrace, Debug, S)
	    end;
	Class:Reason ->
	    Stacktrace = erlang:get_stacktrace(),
	    terminate(Class, Reason, Stacktrace, Debug, S)
    end.

loop_event_result(
  Parent, Debug,
  #{state := State, state_data := StateData} = S,
  Result) ->
    case Result of
	{} -> % Ignore
	    loop_event_consume(
	      Parent, Debug, S, [], State, StateData);
	{NewStateData} -> % Retry
	    loop_event_retry(
	      Parent, Debug, S, [], State, NewStateData);
	{NewState,NewStateData} -> % Consume
	    loop_event_consume(
	      Parent, Debug, S, [], NewState, NewStateData);
	{NewState,NewStateData,StateOps} when is_list(StateOps) ->
	    loop_event_result(
	      Parent, Debug, S, StateOps, NewState, NewStateData);
	StateOps when is_list(StateOps) -> % Stay in state
	    loop_event_result(
	      Parent, Debug, S, StateOps, State, StateData);
	BadReturn ->
	    terminate({bad_return_value,BadReturn}, Debug, S)
    end.

loop_event_result(
  Parent, Debug, S, StateOps, NewState, NewStateData) ->
    %% The 'retry' operation has to be processed first to set
    %% the event queue(s)
    case lists:member(retry, StateOps) of
	true ->
	    loop_event_retry(
	      Parent, Debug, S, StateOps, NewState, NewStateData);
	false ->
	    loop_event_consume(
	      Parent, Debug, S, StateOps, NewState, NewStateData)
    end.

%% Consume the current event
loop_event_consume(
  Parent, Debug,
  #{name := Name, state := State, queue := [Event|Events]} = S,
  StateOps, NewState, NewStateData) ->
    NewDebug =
	case Debug of
	    [] -> Debug;
	    _ ->
		sys:handle_debug(
		  Debug, fun print_event/3,
		  {Name,State}, {consume,Event,NewState})
	end,
    case NewState of
	State ->
	    %% State matches equal - do not retry postponed events
	    loop_state_ops(
	      Parent, NewDebug,
	      S#{state_data := NewStateData, queue := Events},
	      StateOps);
	_ ->
	    %% New state - move all postponed events to queue
	    #{postponed := P} = S,
	    NewQ = lists:reverse(P, Events),
	    loop_state_ops(
	      Parent, NewDebug,
	      S#{
		prev_state := State,
		state := NewState,
		state_data := NewStateData,
		queue := NewQ,
		postponed := []},
	      StateOps)
    end.

%% Postpone the current event
loop_event_retry(
  Parent, Debug,
  #{name := Name,
    state := State,
    queue := [Event|Events] = Q,
    postponed := P} = S,
  StateOps, NewState, NewStateData) ->
    NewDebug =
	case Debug of
	    [] -> Debug;
	    _ ->
		sys:handle_debug(
		  Debug, fun print_event/3,
		  {Name,State}, {retry,Event,NewState})
	end,
    case NewState of
	State ->
	    %% State matches equal - do not retry postponed events
	    %% but postpone the current
	    loop_state_ops(
	      Parent, NewDebug,
	      S#{
		state_data := NewStateData,
		queue := Events,
		postponed := [Event|P]},
	      StateOps);
	_ ->
	    %% New state - move all postponed events and
	    %% the current to queue
	    loop_state_ops(
	      Parent, NewDebug,
	      S#{
		prev_state := State,
		state := NewState,
		state_data := NewStateData,
		queue := lists:reverse(P, Q),
		postponed := []},
	      StateOps)
    end.

%% Loop over StateOps before continuing
loop_state_ops(Parent, Debug, S, []) ->
    loop(Parent, Debug, S);
loop_state_ops(Parent, Debug, S, [StateOp|StateOps]) ->
    case StateOp of
	retry ->
	    %% Ignore 'retry' since it was found with lists:member/2
	    %% in loop_event_result/6 and is already processed
	    loop_state_ops(Parent, Debug, S, StateOps);
	hibernate ->
	    %% Act on 'hibernate' after all operations are processed
	    loop_state_ops(Parent, Debug, S#{hibernate := true}, StateOps);
	{reply,{_To,_Tag}=From,Reply} ->
	    reply(From, Reply),
	    NewDebug =
		case Debug of
		    [] ->
			Debug;
		    _ ->
			#{name := Name, state := State} = S,
			sys:handle_debug(
			  Debug, fun print_event/3,
			  {Name,State}, {out,Reply,From})
		end,
	    loop_state_ops(Parent, NewDebug, S, StateOps);
	{stop,Reason} ->
	    terminate(Reason, Debug, S);
	{insert_event,Type,Content} ->
	    #{queue := Q} = S,
	    loop_state_ops(
	      Parent, Debug,
	      S#{queue := [{Type,Content}|Q]},
	      StateOps);
	{remove_event,Type,Content} ->
	    RemoveFun =
		fun (T, C) when T =:= Type, C =:= Content -> true;
		    (_, _) -> false
		end,
	    loop_state_ops_remove(
	      Parent, Debug, S, StateOps, RemoveFun);
	{remove_event,RemoveFun} when is_function(RemoveFun, 2) ->
	    loop_state_ops_remove(
	      Parent, Debug, S, StateOps, RemoveFun);
	_ ->
	    case remove_fun(StateOp) of
		none ->
		    loop_state_ops(Parent, Debug, S, StateOps);
		{Reason} ->
		    terminate(Reason, Debug, S);
		{Class,Reason,Stacktrace} ->
		    terminate(Class, Reason, Stacktrace, Debug, S);
		RemoveFun when is_function(RemoveFun, 2) ->
		    loop_state_ops_remove(
		      Parent, Debug, S, StateOps, RemoveFun)
	    end
    end;
loop_state_ops(_Parent, Debug, S, StateOps) ->
    terminate({bad_state_op_list,StateOps}, Debug, S).

%% Remove oldest matching event from the queue(s)
loop_state_ops_remove(
  Parent, Debug,
  #{queue := Q, postponed := P} = S,
  StateOps, RemoveFun) ->
    try
	case remove_tail_event(RemoveFun, P) of
	    false ->
		case remove_head_event(RemoveFun, Q) of
		    false ->
			S;
		    NewQ ->
			S#{queue := NewQ}
		end;
	    NewP ->
		S#{postponed := NewP}
	end
    of
	NewS ->
	    loop_state_ops(Parent, Debug, NewS, StateOps)
    catch
	Class:Reason ->
	    terminate(Class, Reason, erlang:get_stacktrace(), Debug, S)
    end.

%%---------------------------------------------------------------------------
%% Server helpers

event(Msg) ->
    case Msg of
	{'$gen_call',From,Request} ->
	    {{call,From},Request};
	{'$gen_event',Event} ->
	    {event,Event};
	_ ->
	    {info,Msg}
%%%
	%% {'$gen_call',From,Request} ->
	%%     {call,From,Request};
	%% {'$gen_event',Event} ->
	%%     {event,Event};
	%% {timeout,TRef,_} when is_reference(TRef) ->
	%%     Msg;
	%% _ ->
	%%     {info,Msg}
%%%
	%% {_} ->
	%%     {Msg};
	%% _ when
	%%       element(1, Msg) =:= call;
	%%       element(1, Msg) =:= event ->
	%%     {Msg};
	%% _ ->
	%%     Msg
    end.



remove_fun({cancel_timer,TimerRef}) ->
    try erlang:cancel_timer(TimerRef) of
	TimeLeft when is_integer(TimeLeft) ->
	    none;
	false ->
	    receive
		{timeout,TimerRef,_} ->
		    ok
	    after 0 ->
		    ok
	    end,
	    fun
		(info, {timeout,TRef,_})
		  when TRef =:= TimerRef ->
		    true;
		(_, _) ->
		    false
	    end
    catch
	Class:Reason ->
	    {Class,Reason,erlang:get_stacktrace()}
    end;
remove_fun({demonitor,MonitorRef}) ->
    try erlang:demonitor(MonitorRef, [flush,info]) of
	false ->
	    none;
	true ->
	    fun (info, {'DOWN',MRef,_,_,_})
		  when MRef =:= MonitorRef->
		    true;
		(_, _) ->
		    false
	    end
    catch
	Class:Reason ->
	    {Class,Reason,erlang:get_stacktrace()}
    end;
remove_fun({unlink,Id}) ->
    try unlink(Id) of
	true ->
	    receive
		{'EXIT',Id,_} ->
		    ok
	    after 0 ->
		    ok
	    end,
	    fun (info, {'EXIT',I,_})
		  when I =:= Id ->
		    true;
		(_, _) ->
		    false
	    end
    catch
	Class:Reason ->
	    {Class,Reason,erlang:get_stacktrace()}
    end;
remove_fun(StateOp) ->
    {{bad_state_op,StateOp}}.



terminate(Reason, Debug, S) ->
    terminate(exit, Reason, [], Debug, S).
%%
terminate(
  Class, Reason, Stacktrace, Debug,
  #{module := Module, state := State, state_data := StateData} = S) ->
    try Module:terminate(Reason, State, StateData) of
	_ -> ok
    catch
	_ -> ok;
	C:R ->
	    ST = erlang:get_stacktrace(),
	    error_info(
	      C, R, ST, Debug, S,
	      format_status(terminate, get(), S)),
	    erlang:raise(C, R, ST)
    end,
    case Reason of
	normal -> ok;
	shutdown -> ok;
	{shutdown,_} -> ok;
	_ ->
	    error_info(
	      Class, Reason, Stacktrace, Debug, S,
	      format_status(terminate, get(), S))
    end,
    case Stacktrace of
	[] ->
	    erlang:Class(Reason);
	_ ->
	    erlang:raise(Class, Reason, Stacktrace)
    end.

error_info(
  Class, Reason, Stacktrace, Debug,
  #{name := Name, state := State, queue := Q},
  FmtStateData) ->
    {FixedReason,FixedStacktrace} =
	case Stacktrace of
	    [{M,F,Args,_}|ST]
	      when Class =:= error, Reason =:= undef ->
		case code:is_loaded(M) of
		    false ->
			{{'module could not be loaded',M},ST};
		    true ->
			Arity = length(Args),
			case erlang:function_exported(M, F, Arity) of
			    true ->
				{Reason,Stacktrace};
			    false ->
				{{'function not exported',{M,F,Arity}},
				 ST}
			end
		end;
	    _ -> {Reason,Stacktrace}
	end,
    error_logger:format(
      "** State machine ~p terminating~n" ++
	  case Q of
	      [] ->
		  "";
	      _ ->
		  "** Last event = ~p~n"
	  end ++
	  "** When State  = ~p~n" ++
	  "**   StateData = ~p~n" ++
	  "** Reason for termination = ~w:~p~n" ++
	  case FixedStacktrace of
	      [] ->
		  "";
	      _ ->
		  "** Stacktrace =~n"
		      "**  ~p~n"
	  end,
      [Name |
       case Q of
	   [] ->
	       [State,FmtStateData,Class,FixedReason];
	   [Event|_] ->
	       [Event,State,FmtStateData,Class,FixedReason]
       end] ++
	  case FixedStacktrace of
	      [] ->
		  [];
	      _ ->
		  [FixedStacktrace]
	  end),
    sys:print_log(Debug),
    ok.



format_status(
  Opt, PDict,
  #{module := Module, state := State, state_data := StateData}) ->
    case erlang:function_exported(Module, format_status, 2) of
	true ->
	    try Module:format_status(Opt, [PDict,State,StateData])
	    catch
		Result -> Result;
		_:_ ->
		    format_status_default(Opt, State, StateData)
	    end;
	false ->
	    format_status_default(Opt, State, StateData)
    end.

format_status_default(Opt, State, StateData) ->
    case Opt of
	terminate ->
	    {State,StateData};
	_ ->
	    [{data,
	      [{"State",State},
	       {"StateData",StateData}]}]
    end.

%%---------------------------------------------------------------------------
%% Farily general helpers

remove_head_event(_RemoveFun, []) ->
    false;
remove_head_event(RemoveFun, [{Tag,Content}|Events]) ->
    case RemoveFun(Tag, Content) of
	false ->
	    remove_head_event(RemoveFun, Events);
	true ->
	    Events
    end.

remove_tail_event(_RemoveFun, []) ->
    false;
remove_tail_event(RemoveFun, [{Tag,Content} = Event|Events]) ->
    case remove_tail_event(RemoveFun, Events) of
	false ->
	    RemoveFun(Tag, Content) andalso Events;
	NewEvents ->
	    [Event|NewEvents]
    end.
