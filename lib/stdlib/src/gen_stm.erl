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
    event/2,call/2,
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
   [wakeup_from_hibernate/6]).

%%% ---------------------------------------------------
%%% Interface functions.
%%% ---------------------------------------------------

-type from() :: {pid(), Tag :: term()}.
-type state() :: atom().
-type data() :: term().
-type event() ::
	{call, from(), term()} |
	{event, term()} |
	{info, term()}.
-type event_action() ::	ok | retry.
-type event_option() ::
	{insert_events, [term()]} |
	{cancel_timer, reference()} |
	{demonitor, reference()} |
	{unlink, pid() | port()} |
	{filter, fun((term()) -> boolean())} |
	hibernate.
-type reason() :: term().

%% This is not a state callback.  It is called only once and
%% the server is not running until this function has returned
%% an {ok, ...} tuple.  Thereafter the state callbacks are called
%% for all events (messages) to this server.
-callback init(Args :: term()) ->
    {ok, InitialState :: state(), InitialData :: data()} |
    {ok, InitialState :: state(), InitialData :: data(),
     [event_option()]} |
    ignore |
    {stop, reason()}.

%% An example callback for state 'init'.
%% Note that state callbacks and only state callbacks have arity 2
%% and that is intentional.  I hope we can guarantee that.
-callback init(Event :: event(), Data :: data()) ->
    {event_action(), NewState :: state(), NewData :: data()} |
    {event_action(), NewState :: state(), NewData :: data(),
     [event_option()]} |
    {stop, reason(), NewData :: data()}.

%% -callback handle_event(Event :: event(), State :: term(), Data :: term()) ->
%%     {event_action(), NewState :: term(), NewData :: term()} |
%%     {event_action(), NewState :: term(), NewData :: term(),
%%      [event_option()]} |
%%     {stop, reason(), NewData :: term()}.

%% Clean up before the server terminates.
-callback terminate(
	    Reason :: normal | shutdown | {shutdown, term()} | reason(),
	    State :: state(),
	    Data :: data()) ->
    any().

-callback code_change(
	    OldVsn :: term() | {down, term()},
	    OldState :: state(),
	    OldData :: data(),
	    Extra :: term()) ->
    {ok, State :: state(), Data :: data()} |
    {ok, State :: state(), Data :: data(), [event_option()]}.

-callback format_status(
	    StatusOption, ProcessDictionary,
	    State :: state(), Data :: data()) ->
    Status :: term() when
      StatusOption :: normal | terminate,
      ProcessDictionary :: [{Key :: term(), Value :: term()}].

-optional_callbacks(
   [format_status/4,
    init/2]).


%%%  -----------------------------------------------------------------
%%%  API

%% Start a state machine
start(Mod, Args, Options) ->
    gen:start(?MODULE, nolink, Mod, Args, Options).
%%
start(Name, Mod, Args, Options) ->
    gen:start(?MODULE, nolink, Name, Mod, Args, Options).

%% Start and link to a state machine
start_link(Mod, Args, Options) ->
    gen:start(?MODULE, link, Mod, Args, Options).
%%
start_link(Name, Mod, Args, Options) ->
    gen:start(?MODULE, link, Name, Mod, Args, Options).

%% Stop a state machine
stop(Name) ->
    gen:stop(Name).
%%
stop(Name, Reason, Timeout) ->
    gen:stop(Name, Reason, Timeout).

%% Send an event to a state machine
event({global,Name}, Event) ->
    try	global:send(Name, event_msg(Event)) of
	_ -> ok
    catch
	_:_ -> ok
    end;
event({via,Mod,Name}, Event) ->
    try	Mod:send(Name, event_msg(Event)) of
	_ -> ok
    catch
	_:_ -> ok
    end;
event({Name,Node} = Dest, Event) when is_atom(Name), is_atom(Node) ->
    send(Dest, event_msg(Event));
event(Dest, Event) when is_atom(Dest) ->
    send(Dest, event_msg(Event));
event(Dest, Event) when is_pid(Dest) ->
    send(Dest, event_msg(Event)).

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

%% Reply from a state machine callback to who is waiting in call/2
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
enter_loop(Module, Options, State, Data) ->
    enter_loop(Module, Options, State, Data, self()).
%%
enter_loop(Module, Options, State, Data, Server) ->
    enter_loop(Module, Options, State, Data, Server, []).
%%
enter_loop(Module, Options, State, Data, Server, EventOpts) ->
    Parent = gen:get_parent(),
    enter(Module, Options, State, Data, Server, EventOpts, Parent).

%%%  -----------------------------------------------------------------
%%%  API helpers

event_msg(Event) ->
    {'$gen_event',Event}.

%% Might actually not send the message
send(Dest, Msg) ->
    try erlang:send(Dest, Msg, [noconnect]) of
	noconnect ->
	    spawn(erlang, send, [Dest,Msg]),
	    ok;
	ok ->
	    ok
    catch
	_:_ ->
	    ok
    end.

enter(Module, Options, State, Data, Server, EventOpts, Parent) ->
    Name = gen:get_proc_name(Server),
    Debug = gen:debug_options(Name, Options),
    %% S =
    %% 	#state{
    %% 	   module = Module,
    %% 	   name = Name,
    %% 	   state = State,
    %% 	   queue = queue:new(),
    %% 	   postponed = queue:new()},
    Hib = false,
    continue(
      Parent, Debug, [Module|Name], [State,[]], Data, Hib, EventOpts).

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
	{ok,State,Data} ->
	    proc_lib:init_ack(Starter, {ok,self()}),
	    enter(Module, Options, State, Data, Server, [], Parent);
	{ok,State,Data,EventOpts} ->
	    proc_lib:init_ack(Starter, {ok,self()}),
	    enter(Module, Options, State, Data, Server, EventOpts, Parent);
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

%% Misc = {ModNam,StateQP,Data}
%% ModNam = [Module|Name]
%% StateQP = [State,Queued|Postponed]


%% -record(state, {module, name, state, queue, postponed}).
%% %% The real state vs. sys is [#state{}|Data]
%% %% where Data is the callback module's state

system_continue(Parent, Debug, {ModNam,StateQP,Data}) ->
    Hib = false,
    continue(Parent, Debug, ModNam, StateQP, Data, Hib).

system_terminate(Reason, _Parent, Debug, {ModNam,StateQP,Data}) ->
    terminate(Reason, Debug, ModNam, StateQP, Data).

system_code_change(
  {[Module|_Name] = ModNam,[State|QP],Data}, _Mod, OldVsn, Extra) ->
    case
	try Module:code_change(OldVsn, State, Data, Extra)
	catch
	    Result -> Result
	end
    of
	{ok,NewState,NewData} ->
	    {ok,{ModNam,[NewState|QP],NewData}};
	BadResult ->
	    {bad_return_value,BadResult}
    end.


%% The state we show to sys tools is a 2-tuple, not a pair
%% to not scare people
system_get_state({_ModNam,[State|_QP],Data}) ->
    {ok,{State,Data}}.

system_replace_state(StateFun, {ModNam,[State|QP],Data}) ->
    {NewState,NewData} = Result = StateFun({State,Data}),
    {ok,Result,{ModNam,[NewState|QP],NewData}}.

format_status(
  Opt,
  [PDict,SysState,Parent,Debug,{[Module|Name],[State,Q|P],Data}]) ->
    Header = gen:format_status_header("Status for state machine", Name),
    Log = sys:get_debug(log, Debug, []),
    [{header,Header},
     {data,
      [{"Status",SysState},
       {"Parent",Parent},
       {"Logged Events",Log},
       {"Queue",Q},
       {"Postponed",P}]} |
     case format_status(Opt, PDict, State, Data, Module) of
	 L when is_list(L) -> L;
	 T -> [T]
     end].

%%-----------------------------------------------------------------
%% Format debug messages.  Print them as the call-back module sees
%% them, not as the real erlang messages.  Use trace for that.
%%-----------------------------------------------------------------
print_event(Dev, {in, Msg}, {Name,State}) ->
    case Msg of
	{call,{From,_Tag},Call} ->
	    io:format(
	      Dev, "*DBG* ~p received call ~p from ~w in state ~w~n",
	      [Name,Call,From,State]);
	{Tag,Event}
	  when Tag =:= event;
	       Tag =:= info ->
	    io:format(
	      Dev, "*DBG* ~p received ~w ~p in state ~w~n",
	      [Name,Tag,Event,State]);
	{Tag,Event,NewState}
	  when Tag =:= ok;
	       Tag =:= retry ->
	    io:format(
	      Dev, "*DBG* ~p returned ~w ~p in state ~w => ~w~n",
	      [Name,Tag,Event,State,NewState]);
	_ ->
	    io:format(
	      Dev, "*DBG* ~p received ~p in state ~w~n",
	      [Name,Msg,State])
    end.

%%%  -----------------------------------------------------------------
%%%  Internal callbacks

wakeup_from_hibernate(
  Parent, Debug, ModNam, StateQP, Data, EventOpts) ->
    Hib = true,
    %% We need to keep this Hib flag around until receive
    continue(Parent, Debug, ModNam, StateQP, Data, Hib, EventOpts).

%%%  -----------------------------------------------------------------
%%%  Implementation

%% The internal state is split over 3 arguments [Mod|Name] = ModNam,
%% [State,Q|P] = StateQP, Data to minimize term rebuild and
%% hereby garbage collect load

%% Loop over EventOpts before continuing
continue(
  Parent, Debug, ModNam, StateQP, Data, Hib, [EventOpt|EventOpts]) ->
    case EventOpt of
	hibernate ->
	    proc_lib:hibernate(
	      ?MODULE, wakeup_from_hibernate,
	      [Parent,Debug,ModNam,StateQP,Data,EventOpts]),
	    ok;
	{insert_events,Events} ->
	    [State,Q|P] = StateQP,
	    continue(
	      Parent, Debug, ModNam,
	      [State,(Q ++ Events)|P],
	      Data, Hib, EventOpts);
	{filter,FilterFun} ->
	    continue(
	      Parent, Debug, ModNam, StateQP, Data,
	      Hib, EventOpts, FilterFun);
	{Type,Ref} ->
	    case filter_fun(Type, Ref) of
		{} ->
		    continue(
		      Parent, Debug, ModNam, StateQP, Data,
		      Hib, EventOpts);
		{Class,Reason,Stacktrace} ->
		    terminate(
		      Class, Reason, Stacktrace, Debug,
		      ModNam, StateQP, Data);
		FilterFun ->
		    continue(
		      Parent, Debug, ModNam, StateQP, Data,
		      Hib, EventOpts, FilterFun)
	    end;
	_ ->
	    terminate(
	      {bad_event_opt,EventOpt},
	      Debug, ModNam, StateQP, Data)
    end;
continue(Parent, Debug, ModNam, StateQP, Data, Hib, []) ->
    continue(Parent, Debug, ModNam, StateQP, Data, Hib);
continue(_Parent, Debug, ModNam, StateQP, Data, _Hib, EventOpts) ->
    terminate(
      {bad_event_opt_list,EventOpts}, Debug, ModNam, StateQP, Data).
%%
%% Filter state due to one EventOpt then continue with the rest
continue(
  Parent, Debug, ModNam, [State,Q|P] = StateQP, Data, Hib,
  EventOpts, FilterFun) ->
    try [[E || E <- Q, FilterFun(E)]|[E || E <- P, FilterFun(E)]] of
	QP ->
	    continue(
	      Parent, Debug, ModNam, [State,QP], Data, Hib, EventOpts)
    catch
	Class:Reason ->
	    terminate(
	      Class, Reason, erlang:get_stacktrace(),
	      Debug, ModNam, StateQP, Data)
    end.
%%
%% Continue with traversing all queued events or receiving a new message
continue(Parent, Debug, ModNam, [State,Q|P] = StateQP, Data, Hib) ->
    case Q of
	[] ->
	    receive
		Msg ->
		    handle_msg(
		      Parent, Debug, ModNam, StateQP, Data, Hib, Msg)
	    end;
	[Event|Events] ->
	    handle_event(
	      Parent, Debug, ModNam, [State,Events|P], Data, Hib, Event)
    end.

filter_fun(cancel_timer, TimerRef) ->
    try erlang:cancel_timer(TimerRef) of
	TimeLeft when is_integer(TimeLeft) ->
	    {};
	false ->
	    receive
		{timeout,TimerRef,_} ->
		    ok
	    after 0 ->
		    ok
	    end,
	    fun
		({timeout,TRef,_}) when TRef =:= TimerRef ->
		    false;
		(_) ->
		    true
	    end
    catch
	Class:Reason ->
	    {Class,Reason,erlang:get_stacktrace()}
    end;
filter_fun(demonitor, MonitorRef) ->
    try erlang:demonitor(MonitorRef, [flush,info]) of
	false ->
	    {};
	true ->
	    fun ({'DOWN',MRef,_,_,_}) when MRef =:= MonitorRef->
		    false;
		(_) ->
		    true
	    end
    catch
	Class:Reason ->
	    {Class,Reason,erlang:get_stacktrace()}
    end;
filter_fun(unlink, Id) ->
    try unlink(Id) of
	true ->
	    receive
		{'EXIT',Id,_} ->
		    ok
	    after 0 ->
		    ok
	    end,
	    fun ({'EXIT',I,_}) when I =:= Id ->
		    false;
		(_) ->
		    true
	    end
    catch
	Class:Reason ->
	    {Class,Reason,erlang:get_stacktrace()}
    end.



terminate(Reason, Debug, ModNam, StateQP, Data) ->
    terminate(exit, Reason, [], Debug, ModNam, StateQP, Data).
%%
terminate(
  Class, Reason, Stacktrace, Debug,
  [Module|_Name] = ModNam, [State|_] = StateQP, Data) ->
    try Module:terminate(Reason, State, Data) of
	_ -> ok
    catch
	_ -> ok;
	C:R ->
	    ST = erlang:get_stacktrace(),
	    error_info(
	      C, R, ST,
	      Debug, ModNam, StateQP,
	      format_status(terminate, get(), State, Data, Module)),
	    erlang:raise(C, R, ST)
    end,
    case Reason of
	normal -> ok;
	shutdown -> ok;
	{shutdown,_} -> ok;
	_ ->
	    error_info(
	      Class, Reason, Stacktrace, Debug, ModNam, StateQP,
	      format_status(terminate, get(), State, Data, Module))
    end,
    case Stacktrace of
	[] ->
	    erlang:Class(Reason);
	_ ->
	    erlang:raise(Class, Reason, Stacktrace)
    end.

error_info(
  Class, Reason, Stacktrace, Debug,
  [_Module|Name], [State,Q|_P], FmtData) ->
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
	  "**   Data = ~p~n" ++
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
	       [State,FmtData,Class,FixedReason];
	   [Event|_] ->
	       [Event,State,FmtData,Class,FixedReason]
       end] ++
	  case FixedStacktrace of
	      [] ->
		  [];
	      _ ->
		  [FixedStacktrace]
	  end),
    sys:print_log(Debug),
    ok.



handle_msg(
  Parent, Debug,
  [_Module|Name] = ModNam,
  [State|_QP] = StateQP,
  Data, Hib, Msg) ->
    case Msg of
	{system,From,Req} ->
	    sys:handle_system_msg(
	      Req, From, Parent, ?MODULE, Debug,
	      {ModNam,StateQP,Data},
	      Hib);
	{'EXIT',Parent,Reason} ->
	    terminate(Reason, Debug, ModNam, StateQP, Data);
	_ when Debug =:= [] ->
	    handle_event(
	      Parent, Debug, ModNam, StateQP, Data, Hib, event(Msg));
	_ ->
	    Event = event(Msg),
	    NewDebug =
		sys:handle_debug(
		  Debug, fun print_event/3, {Name,State}, {in,Event}),
	    handle_event(
	      Parent, NewDebug, ModNam, StateQP, Data, Hib, Event)
    end.


event(Msg) ->
    case Msg of
	{'$gen_call',From,Call} ->
	    {call,From,Call};
	{'$gen_event',Event} ->
	    {event,Event};
	_ ->
	    {info,Msg}
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
  [Module|_Name] = ModNam,
  [State,Q|P] = StateQP,
  Data, Hib, Event) ->
    try Module:State(Event, Data) of
	Result ->
	    handle_event(
	      Parent, Debug, ModNam, StateQP, Data, Hib, Event, Result)
    catch
	Result ->
	    handle_event(
	      Parent, Debug, ModNam, StateQP, Data, Hib, Event, Result);
	error:undef ->
	    StateEQP = [State,[Event|Q]|P],
	    case erlang:get_stacktrace() of
		[{Module,State,[Event,Data]=Args,_}|Stacktrace] ->
		    terminate(
		      error,
		      {undef_state_function,{Module,State,Args}},
		      Stacktrace,
		      Debug, ModNam, StateEQP, Data);
		Stacktrace ->
		    terminate(
		      error, undef, Stacktrace,
		      Debug, ModNam, StateEQP, Data)
	    end;
	Class:Reason ->
	    Stacktrace = erlang:get_stacktrace(),
	    StateEQP = [State,[Event|Q]|P],
	    terminate(
	      Class, Reason, Stacktrace, Debug, ModNam, StateEQP, Data)
    end.
%%
handle_event(
  Parent, Debug, ModNam, StateQP, Data, Hib, Event, Result) ->
    case Result of
	{stop,Reason,NewData} ->
	    terminate(Reason, Debug, ModNam, StateQP, NewData);
	{ok,NewState,NewData} ->
	    handle_event_ok(
	      Parent, Debug, ModNam, StateQP, NewData, Hib, Event,
	      NewState, []);
	{ok,NewState,NewData,EventOpts} ->
	    handle_event_ok(
	      Parent, Debug, ModNam, StateQP, NewData, Hib, Event,
	      NewState, EventOpts);
	{retry,NewState,NewData} ->
	    handle_event_retry(
	      Parent, Debug, ModNam, StateQP, NewData, Hib, Event,
	      NewState, []);
	{retry,NewState,NewData,EventOpts} ->
	    handle_event_retry(
	      Parent, Debug, ModNam, StateQP, NewData, Hib, Event,
	      NewState, EventOpts);
	BadReturn ->
	    [State,Q|P] = StateQP,
	    terminate(
	      {bad_return_value,BadReturn},
	      Debug, ModNam,
	      [State,[Event|Q]|P],
	      Data)
    end.

handle_event_ok(
  Parent, Debug, ModNam, StateQP, NewData, Hib, Event,
  NewState, EventOpts) ->
    NewDebug =
	case Debug of
	    [] -> Debug;
	    _ ->
		[_Module|Name] = ModNam,
		[State|_] = StateQP,
		sys:handle_debug(
		  Debug, fun print_event/3,
		  {Name,State}, {ok,Event,NewState})
	end,
    case StateQP of
	[NewState|_] ->
	    %% State matches equal - do not retry postponed events
	    continue(
	      Parent, NewDebug, ModNam, StateQP, NewData, Hib, EventOpts);
	[_State,Q|P] ->
	    %% New state - move all postponed events to queue
	    continue(
	      Parent, NewDebug, ModNam,
	      [NewState,lists:reverse(P, Q)],
	      NewData, Hib, EventOpts)
    end.

handle_event_retry(
  Parent, Debug, ModNam, StateQP, NewData, Hib, Event,
  NewState, EventOpts) ->
    NewDebug =
	case Debug of
	    [] -> Debug;
	    _ ->
		[_Module|Name] = ModNam,
		[State|_] = StateQP,
		sys:handle_debug(
		  Debug, fun print_event/3,
		  {Name,State}, {retry,Event,NewState})
	end,
    case StateQP of
	[NewState,Q|P] ->
	    %% State matches equal - do not retry postponed events
	    %% but postpone the current
	    continue(
	      Parent, NewDebug, ModNam,
	      [NewState,Q,Event|P],
	      NewData, Hib, EventOpts);
	[_State,Q|P] ->
	    %% New state - move all postponed events and
	    %% the current to queue
	    continue(
	      Parent, NewDebug, ModNam,
	      [NewState,lists:reverse(P, [Event|Q])],
	      NewData, Hib, EventOpts)
    end.



format_status(Opt, PDict, State, Data, Module) ->
    case erlang:function_exported(Module, format_status, 4) of
	true ->
	    try Module:format_status(Opt, PDict, State, Data)
	    catch
		Result -> Result;
		_:_ ->
		    format_status_default(Opt, State, Data)
	    end;
	false ->
	    format_status_default(Opt, State, Data)
    end.

format_status_default(Opt, State, Data) ->
    case Opt of
	terminate ->
	    {State,Data};
	_ ->
	    [{data,
	      [{"State",State},
	       {"Data",Data}]}]
    end.
