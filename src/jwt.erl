%% @author: Andrey
%% @date: 16.04.2015

-module(jwt).

%% Include files

%% Exported Functions

-export([
    decode/2,
    decode/3,
    is_expired/1
]).

-export_type([jwt/0, claims/0]).

-type jwt() :: binary().
-type claims() :: jsx:json_term().
-type step() :: {'jws', jwk:jwk()} | {'jws', 'none'} | {'jwe', jwk:jwk()}.

%%%===================================================================
%%% API
%%%===================================================================

-spec decode(jwt(), jwk:jwk_set()) -> {claims(), [step()]}.

decode(JWT, Keys) ->
    decode(JWT, Keys, []).

-spec decode(jwt(), jwk:jwk_set(), [term()]) -> {claims(), [step()]}.

decode(JWT, Keys, Options) ->
    decode_steps(JWT, Keys, Options, []).

-spec is_expired(claims()) -> boolean().

is_expired(#{exp := Exp}) ->
    jose_utils:unix_timestamp() > Exp;
is_expired(#{}) ->
    false.    

%%%===================================================================
%%% Internal functions
%%%===================================================================

decode_steps(JWT, Keys, Options, Steps) ->
    Header = header(JWT),
    IsJWT = maps:get(cty, Header, undefined) =:= <<"JWT">>,
    IsJWE = maps:is_key(enc, Header),
    {JWT1, NewSteps} =
        case IsJWE of
            true ->
                {Payload, Result} = jwe:decode_compact(JWT, Keys, Options),
                {Payload, [Result | Steps]};
            false ->
                {_, Payload, Result} = jws:decode_compact(JWT, Keys, Options),
                {Payload, [Result | Steps]}
        end,
    case IsJWT of
        true -> decode_steps(JWT1, Keys, Options, NewSteps);
        false -> {jose_utils:decode_json(JWT1), NewSteps}
    end.

header(JWT) ->
    EncodedHeader = hd(binary:split(JWT, <<$.>>)),
    jose_utils:decode_json(jose_base64url:decode(EncodedHeader)).

