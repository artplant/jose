%% @author: Andrey
%% @date: 17.04.2015

-module(jws).

%% Include files
-include("jose.hrl").
-include("assert.hrl").

%% Exported Functions

-export([
    encode_compact/3,
    decode_compact/2,
    decode_compact/3,
    decode_json/3,
    decode_json/2
]).

-type jws_compact() :: binary().
-type jose_header() :: jsx:json_term().

-type decode_options() :: [decode_option()].
-type decode_option() :: 'accept_unsecured' | {'accepted_jws_algs', [jwa:jws_alg()]}.

-type jwks() :: jwk:jwk() | jwk:jwk_set() | [jwk:jwk()].

-type jws_verify_result() :: #jws_verify_result{}.

%%%===================================================================
%%% API
%%%===================================================================

-spec encode_compact(binary(), jose_header(), jwk:jwk() | 'undefined') -> jws_compact().

encode_compact(Payload, JoseHeader, JWK) ->
    Base64UrlProtectedHeader = jose_base64url:encode(jose_utils:encode_json(JoseHeader)),
    Base64UrlPayload = jose_base64url:encode(Payload),
    #{alg := Alg} = JoseHeader,
    SigningInput = signing_input(Base64UrlProtectedHeader, Base64UrlPayload),
    Signature = jwa:sign(Alg, SigningInput, JWK),
    Base64UrlSignature = jose_base64url:encode(Signature),
    <<SigningInput/binary, $., Base64UrlSignature/binary>>.

-spec decode_compact(jws_compact(), jwks()) -> {boolean(), binary(), jws_verify_result()}.

decode_compact(JWS, Keys) ->
    decode_compact(JWS, Keys, []).

-spec decode_compact(jws_compact(), jwks(), decode_options()) -> {boolean(), binary(), jws_verify_result()}.

decode_compact(JWS, Keys, Options) ->
    [Base64UrlProtectedHeader, Base64UrlPayload, Base64UrlSignature] = binary:split(JWS, <<$.>>, [global]),
    Result = verify_signature(undefined, Base64UrlProtectedHeader, Base64UrlPayload, Base64UrlSignature, Keys, Options),
    {Result#jws_verify_result.is_verified, jose_base64url:decode(Base64UrlPayload), Result}.

-spec decode_json(jsx:json_term(), jwks()) -> {boolean(), binary(), [jws_verify_result()]}.

decode_json(JWS, Keys) ->
    decode_json(JWS, Keys, []).
    
-spec decode_json(jsx:json_term(), jwks(), decode_options()) -> {boolean(), binary(), [jws_verify_result()]}.

decode_json(JWS, Keys, Options) ->
    #{payload := Base64UrlPayload} = JWS,
    Results =
        case maps:get(signatures, JWS, undefined) of
            undefined ->
                [ verify_json_signature(JWS, Base64UrlPayload, Keys, Options) ];
            Signatures ->
                [ verify_json_signature(Json, Base64UrlPayload, Keys, Options) || Json <- Signatures ]
        end,
    IsVerified = lists:all(fun(R) -> R#jws_verify_result.is_verified end, Results),
    {IsVerified, jose_base64url:decode(Base64UrlPayload), Results}.

%%%===================================================================
%%% Internal functions
%%%===================================================================

signing_input(undefined, Base64UrlSignature) ->
    <<$., Base64UrlSignature/binary>>;
signing_input(Base64UrlProtectedHeader, Base64UrlSignature) ->
    <<Base64UrlProtectedHeader/binary, $., Base64UrlSignature/binary>>.

complete_header(undefined, undefined) ->
    error(no_jws_header_found);
complete_header(undefined, ProtectedHeader) ->
    ProtectedHeader;
complete_header(UnprotectedHeader, undefined) ->
    UnprotectedHeader;
complete_header(UnprotectedHeader, ProtectedHeader) ->
    maps:merge(UnprotectedHeader, ProtectedHeader).

verify_json_signature(Json, Base64UrlPayload, Keys, Options) ->
    UnprotectedHeader = maps:get(header, Json, undefined),
    Base64UrlProtectedHeader = maps:get(protected, Json, undefined),
    Base64UrlSignature = maps:get(signature, Json),
    verify_signature(UnprotectedHeader, Base64UrlProtectedHeader, Base64UrlPayload, Base64UrlSignature, Keys, Options).

verify_signature(UnprotectedHeader, Base64UrlProtectedHeader, Base64UrlPayload, Base64UrlSignature, Keys, Options) ->
    Signature = jose_base64url:decode(Base64UrlSignature),
    SigningInput = signing_input(Base64UrlProtectedHeader, Base64UrlPayload),
    ProtectedHeader =
        case Base64UrlProtectedHeader of
            undefined -> undefined;
            _ -> jose_utils:decode_json(jose_base64url:decode(Base64UrlProtectedHeader))
        end,
    Header = complete_header(UnprotectedHeader, ProtectedHeader),
    Alg = maps:get(alg, Header),
    try
        ?assertThrow(is_accepted_alg(Alg, Options), {jws_alg_not_accepted, Alg}),
        Key =
            case Alg of
                <<"none">> ->
                    ?assertThrow(proplists:get_value(accept_unsecured, Options, false), unsecured_not_accepted),
                    ?assertThrow(Signature =:= <<>>, invalid_signature),
                    undefined;
                _ ->
                    SelectedKeys = jose_keys:select_keys(Header, Keys),
                    verify_any(Alg, SigningInput, Signature, SelectedKeys)
            end,
        #jws_verify_result{is_verified = true, header = Header, alg = Alg, jwk = Key}
    catch
        Throw -> #jws_verify_result{is_verified = false, error = Throw, header = Header, alg = Alg}
    end.

is_accepted_alg(Alg, Options) ->
    case proplists:get_value(accepted_jws_algs, Options) of
        undefined -> true;
        List -> lists:member(Alg, List)
    end.

verify_any(Alg, SigningInput, Signature, [JWK|Keys]) ->
    try jwa:verify(Alg, SigningInput, Signature, JWK) of
        true -> JWK;
        false -> verify_any(Alg, SigningInput, Signature, Keys)
    catch
        error:badkey -> verify_any(Alg, SigningInput, Signature, Keys)
    end;
verify_any(_Alg, _SigningInput, _Signature, []) ->
    throw(verify_failed).