#!/usr/bin/env escript
%% SPDX-License-Identifier: Apache-2.0
%% Copyright 2026 Sudo Apt Holdings LLC (Script Kitty OS & Labs)
%% Cross-check: pure ML-DSA-87, EMPTY context, through Erlang :crypto (OpenSSL 3.5+).
%% Input: one case per line, "ID PK_HEX SIG_HEX MSG_HEX" (MSG_HEX may be "-" for empty).
%% Output: "ID true|false|error" per line, then "info <crypto:info_lib()>".
%% OTP's :crypto takes no ML-DSA context argument, so only empty-context cases can be checked.
main([Path]) ->
    {ok, _} = application:ensure_all_started(crypto),
    {ok, Bin} = file:read_file(Path),
    Lines = [L || L <- binary:split(Bin, <<"\n">>, [global]), L =/= <<>>],
    lists:foreach(fun(L) ->
        [Id, Pk, Sig, Msg0] = binary:split(L, <<" ">>, [global]),
        Msg = case Msg0 of <<"-">> -> <<>>; _ -> binary:decode_hex(Msg0) end,
        R = try crypto:verify(mldsa87, none, Msg, binary:decode_hex(Sig), binary:decode_hex(Pk)) of
                true -> "true"; false -> "false"
            catch _:_ -> "error" end,
        io:format("~s ~s~n", [Id, R])
    end, Lines),
    io:format("info ~p~n", [crypto:info_lib()]).
