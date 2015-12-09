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
   [wakeup_from_hibernate/4]).

%%% ---------------------------------------------------
%%% Interface functions.
%%% ---------------------------------------------------

-type from() :: {pid(), Tag :: term()}.
-type state() :: atom().
-type state_data() :: term().
-type event_type() :: call | event | info.
-type call_event_content() :: {from(), Request :: term()}.
-type event_content() :: call_event_content() | term().
-type remove_event_predicate() ::
	fun((event_type(), event_content()) -> boolean()).
-type reason() :: term().
-type state_op() ::
	retry |
	hibernate |
	{stop, reason()} |
	{insert_event, event_type(), event_content()} |
	{remove_event, event_type(), event_content()} |
	{remove_event, remove_event_predicate()} |
	{cancel_timer, TimerRef :: reference()} |
	{demonitor, MonitorRef :: reference()} |
	{unlink, Id :: pid() | port()}.
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
%% Note that state callbacks and only state callbacks have arity 4
%% and that is intentional.  I hope we can guarantee that.
-callback init(
	    PrevState :: state(),
	    event_type(),
	    event_content(),
	    StateData :: state_data()) ->
    [state_op()] |
    {} |
    {NewStateData :: state_data()} |
    {NewState :: state(), NewStateData :: state_data()} |
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

-callback code_change(
	    {OldVsn :: term() | {down, term()}, Extra :: term()},
	    OldState :: state(),
	    OldStateData :: state_data()) ->
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
    init/4]).


%%%  -----------------------------------------------------------------
%%%  API

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

%% Send an message to a state machine
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

%% Send an event to a state machine
event(Server, Event) ->
    send(Server, event_msg(Event)).

%% Call a state machine (synchronous; a reply is expected)
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
%% started by proc_lib into a state machine supplying
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

%%%  -----------------------------------------------------------------
%%%  API helpers

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
      postponed => []},
    Hib = false,
    continue(Parent, Debug, S, Hib, StateOps).

%%%  -----------------------------------------------------------------
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

%%%  -----------------------------------------------------------------
%%%  gen callbacks helpers

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

%%%  -----------------------------------------------------------------
%%%  sys callbacks

system_continue(Parent, Debug, S) ->
    Hib = false,
    continue(Parent, Debug, S, Hib).

system_terminate(Reason, _Parent, Debug, S) ->
    terminate(Reason, Debug, S).

system_code_change(
  #{module := Module,
    prev_state := Pstate,
    state := State,
    state_data := StateData} = S,
  _Mod, OldVsn, Extra) ->
    case
	try Module:code_change(OldVsn, {Pstate, State, StateData}, Extra)
	catch
	    Result -> Result
	end
    of
	{ok,{NewPstate,NewState,NewStateData}} ->
	    {ok,
	     S#{
	       prev_state := NewPstate,
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

%%-----------------------------------------------------------------
%% Format debug messages.  Print them as the call-back module sees
%% them, not as the real erlang messages.  Use trace for that.
%%-----------------------------------------------------------------
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


%%%  -----------------------------------------------------------------
%%%  Internal callbacks

wakeup_from_hibernate(Parent, Debug, S, StateOps) ->
    Hib = true,
    %% We need to keep this Hib flag around until receive
    continue(Parent, Debug, S, Hib, StateOps).

%%%  -----------------------------------------------------------------
%%%  Implementation

%% Loop over StateOps before continuing
continue(
  Parent, Debug, #{queue := Q} = S, Hib, [StateOp|StateOps]) ->
    case StateOp of
	retry ->
	    %% Ignore 'retry' since it is found with lists:member/2
	    %% in handle_event_result/8
	    continue(Parent, Debug, S, Hib, StateOps);
	hibernate ->
	    proc_lib:hibernate(
	      ?MODULE, wakeup_from_hibernate, [Parent,Debug,S,StateOps]),
	    ok;
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
	    continue(Parent, NewDebug, S, Hib, StateOps);
	{stop,Reason} ->
	    terminate(Reason, Debug, S);
	{insert_event,Type,Content} ->
	    continue(
	      Parent, Debug,
	      S#{queue := [{Type,Content}|Q]},
	      Hib, StateOps);
	{remove_event,Type,Content} ->
	    RemoveFun =
		fun (T, C) when T =:= Type, C =:= Content -> true;
		    (_, _) -> false
		end,
	    continue_remove(
	      Parent, Debug, S, Hib, StateOps, RemoveFun);
	{remove_event,RemoveFun} ->
	    continue_remove(
	      Parent, Debug, S, Hib, StateOps, RemoveFun);
	_ ->
	    case remove_fun(StateOp) of
		[] ->
		    continue(Parent, Debug, S, Hib, StateOps);
		[Reason] ->
		    terminate(Reason, Debug, S);
		[Class,Reason,Stacktrace] ->
		    terminate(Class, Reason, Stacktrace, Debug, S);
		RemoveFun ->
		    continue_remove(
		      Parent, Debug, S, Hib, StateOps, RemoveFun)
	    end
    end;
continue(Parent, Debug, S, Hib, []) ->
    continue(Parent, Debug, S, Hib);
continue(_Parent, Debug, S, _Hib, StateOps) ->
    terminate({bad_state_op_list,StateOps}, Debug, S).
%%
%% Continue with traversing all queued events or receiving a new message
continue(Parent, Debug, S, Hib) ->
    case S of
	#{queue := []} ->
	    %% Receive a new message
	    receive
		Msg ->
		    handle_msg(Parent, Debug, S, Hib, Msg)
	    end;
	#{queue := [Event|Q]} ->
	    %% Pick a message from the queue
	    handle_event(Parent, Debug, S#{queue := Q}, Hib, Event)
    end.

%% Remove oldest matching event from the queue(s)
continue_remove(
  Parent, Debug,
  #{queue := Q, postponed := P} = S,
  Hib, StateOps, RemoveFun) ->
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
	    continue(Parent, Debug, NewS, Hib, StateOps)
    catch
	Class:Reason ->
	    terminate(Class, Reason, erlang:get_stacktrace(), Debug, S)
    end.

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

remove_fun({cancel_timer,TimerRef}) ->
    try erlang:cancel_timer(TimerRef) of
	TimeLeft when is_integer(TimeLeft) ->
	    [];
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
	    [Class,Reason,erlang:get_stacktrace()]
    end;
remove_fun({demonitor,MonitorRef}) ->
    try erlang:demonitor(MonitorRef, [flush,info]) of
	false ->
	    [];
	true ->
	    fun (info, {'DOWN',MRef,_,_,_})
		  when MRef =:= MonitorRef->
		    true;
		(_, _) ->
		    false
	    end
    catch
	Class:Reason ->
	    [Class,Reason,erlang:get_stacktrace()]
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
	    [Class,Reason,erlang:get_stacktrace()]
    end;
remove_fun(StateOp) ->
    [{bad_state_op,StateOp}].



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



handle_msg(Parent, Debug, #{name := Name, state := State} = S, Hib, Msg) ->
    case Msg of
	{system,From,Req} ->
	    sys:handle_system_msg(Req, From, Parent, ?MODULE, Debug, S, Hib);
	{'EXIT',Parent,Reason} ->
	    terminate(Reason, Debug, S);
	_ when Debug =:= [] ->
	    handle_event(Parent, Debug, S, Hib, event(Msg));
	_ ->
	    Event = event(Msg),
	    NewDebug =
		sys:handle_debug(
		  Debug, fun print_event/3, {Name,State}, {in,Event}),
	    handle_event(Parent, NewDebug, S, Hib, Event)
    end.

event(Msg) ->
    case Msg of
	{'$gen_call',From,Request} ->
	    {call,{From,Request}};
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

handle_event(
  Parent, Debug,
  #{module := Module,
    prev_state := PrevState,
    state := State,
    state_data := StateData,
    queue := Q} = S,
  Hib, {Type,Content} = Event) ->
    try Module:State(PrevState, Type, Content, StateData) of
	Result ->
	    handle_event_result(Parent, Debug, S, Hib, Event, Result)
    catch
	Result ->
	    handle_event_result(Parent, Debug, S, Hib, Event, Result);
	error:undef ->
	    case erlang:get_stacktrace() of
		[{Module,State,[Event,StateData]=Args,_}|Stacktrace] ->
		    terminate(
		      error,
		      {undef_state_function,{Module,State,Args}},
		      Stacktrace,
		      Debug,
		      S#{queue := [Event|Q]});
		Stacktrace ->
		    terminate(
		      error, undef, Stacktrace, Debug,
		      S#{queue := [Event|Q]})
	    end;
	Class:Reason ->
	    Stacktrace = erlang:get_stacktrace(),
	    terminate(
	      Class, Reason, Stacktrace, Debug,
	      S#{queue := [Event|Q]})
    end.

handle_event_result(
  Parent, Debug,
  #{state := State, state_data := StateData, queue := Q} = S,
  Hib, Event, Result) ->
    case Result of
	{} -> % Ignore
	    handle_event_accept(
	      Parent, Debug, S, Hib, [],
	      State, StateData, Event);
	{NewStateData} -> % Postpone
	    handle_event_retry(
	      Parent, Debug, S, Hib, [],
	      State, NewStateData, Event);
	{NewState,NewStateData} -> % Consume
	    handle_event_accept(
	      Parent, Debug, S, Hib, [],
	      NewState, NewStateData, Event);
	{NewState,NewStateData,StateOps} when is_list(StateOps) ->
	    handle_event_result(
	      Parent, Debug, S, Hib, StateOps,
	      NewState, NewStateData, Event);
	StateOps when is_list(StateOps) ->
	    handle_event_result(
	      Parent, Debug, S, Hib, StateOps,
	      State, StateData, Event);
	BadReturn ->
	    terminate(
	      {bad_return_value,BadReturn}, Debug,
	      S#{queue := [Event|Q]})
    end.

handle_event_result(
  Parent, Debug, S, Hib, StateOps, NewState, NewStateData, Event) ->
    case lists:member(retry, StateOps) of
	true ->
	    handle_event_retry(
	      Parent, Debug, S, Hib, StateOps,
	      NewState, NewStateData, Event);
	false ->
	    handle_event_accept(
	      Parent, Debug, S, Hib, StateOps,
	      NewState, NewStateData, Event)
    end.

handle_event_accept(
  Parent, Debug,
  #{name := Name, state := State} = S,
  Hib, StateOps, NewState, NewStateData, Event) ->
    NewDebug =
	case Debug of
	    [] -> Debug;
	    _ ->
		sys:handle_debug(
		  Debug, fun print_event/3,
		  {Name,State}, {accept,Event,NewState})
	end,
    case NewState of
	State ->
	    %% State matches equal - do not retry postponed events
	    continue(
	      Parent, NewDebug,
	      S#{state_data := NewStateData},
	      Hib, StateOps);
	_ ->
	    %% New state - move all postponed events to queue
	    #{queue := Q, postponed := P} = S,
	    NewQ = lists:reverse(P, Q),
	    continue(
	      Parent, NewDebug,
	      S#{
		prev_state := State,
		state := NewState,
		state_data := NewStateData,
		queue := NewQ,
		postponed := []},
	      Hib, StateOps)
    end.

handle_event_retry(
  Parent, Debug,
  #{name := Name, state := State} = S,
  Hib, StateOps, NewState, NewStateData, Event) ->
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
	    #{postponed := P} = S,
	    continue(
	      Parent, NewDebug,
	      S#{state_data := NewStateData, postponed := [Event|P]},
	      Hib, StateOps);
	_ ->
	    %% New state - move all postponed events and
	    %% the current to queue
	    #{queue := Q, postponed := P} = S,
	    NewQ = lists:reverse(P, [Event|Q]),
	    continue(
	      Parent, NewDebug,
	      S#{
		prev_state := State,
		state := NewState,
		state_data := NewStateData,
		queue := NewQ,
		postponed := []},
	      Hib, StateOps)
    end.



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
