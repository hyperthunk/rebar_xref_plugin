%% The contents of this file are subject to the Mozilla Public License
%% Version 1.1 (the "License"); you may not use this file except in
%% compliance with the License. You may obtain a copy of the License
%% at http://www.mozilla.org/MPL/
%%
%% Software distributed under the License is distributed on an "AS IS"
%% basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See
%% the License for the specific language governing rights and
%% limitations under the License.
%%
%% The Original Code is RabbitMQ.
%%
%% The Initial Developer of the Original Code is VMware, Inc.
%% Copyright (c) 2010-2012 VMware, Inc.  All rights reserved.
%%
-module(rebar_xref_plugin).

main(Config, _) ->
    %% TODO: Urgh, don't use the process dictionary for this...
    put({?MODULE, quiet}, rebar_config:get_local(Config, xref_quiet, false)),
    put({?MODULE, no_filters},
        rebar_config:get_local(Config, xref_no_filters, false)),

    {ok, Cwd} = file:get_cwd(),
    code:add_pathz(filename:join(Cwd, "ebin")),
    LibDir = filename:join(Cwd, "lib"),
    case filelib:is_dir(LibDir) of
        false -> ok;
        true  -> os:cmd("rm -rf " ++ LibDir)
    end,

    try
        check(Cwd, PluginsDir, LibDir, checks())
    after
        %% TODO: bootstrap file_handle_cache and use
        %% rabbit_file:recursive_delete instead of this...
        os:cmd("rm -rf " ++ LibDir)
    end.

check(Cwd, PluginsDir, LibDir, Checks) ->
    xref:start(?MODULE),
    xref:set_default(?MODULE, [{verbose, false}, {warnings, false}]),
    xref:set_library_path(?MODULE, code:get_path()),
    %% TODO: get the app-id from rebar_config
    xref:add_release(?MODULE, Cwd, {name, rebar_xref}),
    store_unresolved_calls(),
    Results = lists:flatten([perform_analysis(Q) || Q <- Checks]),
    report(Results).

%%
%% Analysis
%%

perform_analysis({Query, Description, Severity}) ->
    perform_analysis({Query, Description, Severity, fun(_) -> false end});
perform_analysis({Query, Description, Severity, Filter}) ->
    report_progress("Checking whether any code ~s "
                    "(~s)~n", [Description, Query]),
    case analyse(Query) of
        {ok, Analysis} ->
            [filter(Result, Filter) ||
                Result <- process_analysis(Query, Description,
                                           Severity, Analysis)];
        {error, Module, Reason} ->
            {analysis_error, {Module, Reason}}
    end.

partition(Results) ->
    lists:partition(fun({{_, L}, _}) -> L =:= error end, Results).

analyse(Query) when is_atom(Query) ->
    xref:analyse(?MODULE, Query, [{verbose, false}]);
analyse(Query) when is_list(Query) ->
    xref:q(?MODULE, Query).

process_analysis(Query, Tag, Severity, Analysis) when is_atom(Query) ->
    [{{Tag, Severity}, MFA} || MFA <- Analysis];
process_analysis(Query, Tag, Severity, Analysis) when is_list(Query) ->
    [{{Tag, Severity}, Result} || Result <- Analysis].

checks() ->
   [{"(XXL)(Lin) ((XC - UC) || (XU - X - B))",
     "has call to undefined function(s)",
        error, filters()},
    {"(Lin) (L - LU)", "has unused local function(s)",
        error, filters()},
    {"(Lin) (LU * (X - XU))",
        "has exported function(s) only used locally",
        warning, filters()},
    {"(Lin) (DF * (XU + LU))", "used deprecated function(s)",
        warning, filters()}].
%    {"(Lin) (X - XU)", "possibly unused export",
%        warning, fun filter_unused/1}].

%%
%% noise filters (can be disabled with -X) - strip uninteresting analyses
%%

filter(Result, Filter) ->
    case Filter(Result) of
        false -> Result;
        true  -> []  %% NB: this gets flattened out later on....
    end.

filters() ->
    case get({?MODULE, no_filters}) of
        true  -> fun(_) -> false end;
        _     -> filter_chain([fun is_unresolved_call/1, fun is_callback/1,
                               fun is_unused/1, fun is_irrelevant/1])
    end.

filter_chain(FnChain) ->
    fun(AnalysisResult) ->
        lists:foldl(fun(F, false) -> F(cleanup(AnalysisResult));
                       (_F, true) -> true
                    end, false, FnChain)
    end.

cleanup({{_, _},{{{{_,_,_}=MFA1,_},{{_,_,_}=MFA2,_}},_}}) -> {MFA1, MFA2};
cleanup({{_, _},{{{_,_,_}=MFA1,_},{{_,_,_}=MFA2,_}}})     -> {MFA1, MFA2};
cleanup({{_, _},{{_,_,_}=MFA1,{_,_,_}=MFA2},_})           -> {MFA1, MFA2};
cleanup({{_, _},{{_,_,_}=MFA1,{_,_,_}=MFA2}})             -> {MFA1, MFA2};
cleanup({{_, _}, {_,_,_}=MFA})                            -> MFA;
cleanup({{_, _}, {{_,_,_}=MFA,_}})                        -> MFA;
cleanup({{_,_,_}=MFA, {_,_,_}})                           -> MFA;
cleanup({{_,_,_}=MFA, {_,_,_},_})                         -> MFA;
cleanup(Other)                                            -> Other.

is_irrelevant({{M,_,_}, {_,_,_}}) ->
    is_irrelevant(M);
is_irrelevant({M,_,_}) ->
    is_irrelevant(M);
is_irrelevant(Mod) when is_atom(Mod) ->
    lists:member(Mod, get({?MODULE, third_party})).

is_unused({{_,_,_}=MFA, {_,_,_}}) ->
    is_unused(MFA);
is_unused({M,_F,_A}) ->
    lists:suffix("_tests", atom_to_list(M));
is_unused(_) ->
    false.

is_unresolved_call({_, F, A}) ->
    UC = get({?MODULE, unresolved_calls}),
    sets:is_element({'$M_EXPR', F, A}, UC);
is_unresolved_call(_) ->
    false.

%% TODO: cache this....
is_callback({M,_,_}=MFA) ->
    Attributes = M:module_info(attributes),
    Behaviours = proplists:append_values(behaviour, Attributes),
    {_, Callbacks} = lists:foldl(fun acc_behaviours/2, {M, []}, Behaviours),
    lists:member(MFA, Callbacks);
is_callback(_) ->
    false.

acc_behaviours(B, {M, CB}=Acc) ->
    case catch(B:behaviour_info(callbacks)) of
        [{_,_} | _] = Callbacks ->
            {M, CB ++ [{M, F, A} || {F,A} <- Callbacks]};
        _ ->
            Acc
    end.

%%
%% reporting/output
%%

report(Results) ->
    [report_failures(F) || F <- Results],
    {Errors, Warnings} = partition(Results),
    report(info, "Completed: ~p errors, ~p warnings~n",
                 [length(Errors), length(Warnings)]),
    case length(Errors) > 0 of
        true  -> halt(1);
        false -> halt(0)
    end.

report_failures({analysis_error, {Mod, Reason}}) ->
    report(error, "~s:0 Analysis Error: ~p~n", [source_file(Mod), Reason]);
report_failures({{Tag, Level}, {{{{M,_,_},L},{{M2,F2,A2},_}},_}}) ->
    report(Level, "~s:~w ~s ~p:~p/~p~n",
           [source_file(M), L, Tag, M2, F2, A2]);
report_failures({{Tag, Level}, {{M,F,A},L}}) ->
    report(Level, "~s:~w ~s ~p:~p/~p~n", [source_file(M), L, Tag, M, F, A]);
report_failures({{Tag, Level}, {M,F,A}}) ->
    report(Level, "~s:unknown ~s ~p:~p/~p~n", [source_file(M), Tag, M, F, A]);
report_failures(Term) ->
    report(error, "Ignoring ~p~n", [Term]),
    ok.

report_progress(Fmt, Args) ->
    report(info, Fmt, Args).

report(Level, Fmt, Args) ->
    case {get({?MODULE, quiet}), Level} of
        {true,  error} -> do_report(lookup_prefix(Level), Fmt, Args);
        {false, _}     -> do_report(lookup_prefix(Level), Fmt, Args);
        _              -> ok
    end.

do_report(Prefix, Fmt, Args) ->
    io:format(Prefix ++ Fmt, Args).

lookup_prefix(error)   -> "ERROR: ";
lookup_prefix(warning) -> "WARNING: ";
lookup_prefix(info)    -> "INFO: ".

source_file(M) ->
    proplists:get_value(source, M:module_info(compile)).

%%
%% setup/code-path/file-system ops
%%

store_third_party(App) ->
    {ok, AppConfig} = application:get_all_key(App),
    case get({?MODULE, third_party}) of
        undefined ->
            put({?MODULE, third_party},
                proplists:get_value(modules, AppConfig));
        Modules ->
            put({?MODULE, third_party},
                proplists:get_value(modules, AppConfig) ++ Modules)
    end.

%% TODO: this ought not to be maintained in such a fashion
external_dependency(Path) ->
    lists:any(fun(P) -> lists:prefix(P, Path) end,
              ["mochiweb", "webmachine", "rfc4627", "eldap"]).

unmangle_name(Path) ->
    [Name, Vsn | _] = re:split(Path, "-", [{return, list}]),
    string:join([Name, Vsn], "-").

store_unresolved_calls() ->
    {ok, UCFull} = analyse("UC"),
    UC = [MFA || {_, {_,_,_} = MFA} <- UCFull],
    put({?MODULE, unresolved_calls}, sets:from_list(UC)).
