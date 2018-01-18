%% @author: Andrey
%% @date: 16.04.2015

-module(jwe).

%% Include files
-include("jose.hrl").
-include("assert.hrl").

%% Exported Functions

-export([
    decode_compact/2,
    decode_compact/3,
    encode_compact/4,
    encode_compact/3
]).

-type jwe_compact() :: binary().

-type decode_options() :: [decode_option()].
-type decode_option() :: {'jwe_draft', pos_integer()}.

-type jwks() :: jwk:jwk() | jwk:jwk_set() | [jwk:jwk()].

-type jwe_decrypt_result() :: #jwe_decrypt_result{}.

%%%===================================================================
%%% API
%%%===================================================================

-spec decode_compact(jwe_compact(), jwks()) -> {binary(), jwe_decrypt_result()}.

decode_compact(JWE, Keys) ->
    decode_compact(JWE, Keys, []).

-spec decode_compact(jwe_compact(), jwks(), decode_options()) -> {binary(), jwe_decrypt_result()}.

decode_compact(JWE, Keys, Options) ->
    Draft = proplists:get_value(jwe_draft, Options, 40),
    [ Base64UrlProtectedHeader, Base64UrlEncryptedKey, Base64UrlInitializationVector, Base64UrlCiphertext, Base64UrlAuthenticationTag ] = binary:split(JWE, <<$.>>, [global]),
    ProtectedHeader = jose_base64url:decode(Base64UrlProtectedHeader),
    EncryptedKey = jose_base64url:decode(Base64UrlEncryptedKey),
    InitializationVector = jose_base64url:decode(Base64UrlInitializationVector),
    Ciphertext = jose_base64url:decode(Base64UrlCiphertext),
    AuthenticationTag = jose_base64url:decode(Base64UrlAuthenticationTag),
    JoseHeader = jose_utils:decode_json(ProtectedHeader),
    #{alg := Alg, enc := Enc} = JoseHeader,
    AAD = additional_authentication_data(Base64UrlProtectedHeader, Base64UrlEncryptedKey, Base64UrlInitializationVector, Draft),
    MatchingKeys = jose_keys:select_keys(JoseHeader, Keys),
    {DecryptedData, JWK} = decode_any(Alg, Enc, JoseHeader, EncryptedKey, Ciphertext, InitializationVector, AAD, AuthenticationTag, MatchingKeys),
    Result = #jwe_decrypt_result{alg = Alg, enc = Enc, header = JoseHeader, jwk = JWK},
    Zip = maps:get(zip, JoseHeader, undefined),
    {decompress(Zip, DecryptedData), Result}.

encode_compact(Plaintext, JoseHeader, JWK) ->
    encode_compact(Plaintext, JoseHeader, JWK, []).

encode_compact(Plaintext, JoseHeader, JWK, Options) ->
    Draft = proplists:get_value(jwe_draft, Options, 40),
    #{alg := Alg, enc := Enc} = JoseHeader,
    Mode = jwa:key_management_mode(Alg),
    AgreedKey =
        if 
            Mode =:= direct_key_agreement; Mode =:= key_agreement_with_key_wrapping ->
                jwa:producer_agreed_key(Alg, JWK, proplists:get_value(private_ephemeral_key, Options), JoseHeader);
            true ->
                undefined
        end,            
    CEK =
        case Mode of
            direct_key_agreement ->
                AgreedKey;
            _ ->
                crypto:strong_rand_bytes(jwa:cek_size(Enc))
        end,
    EncryptedKey =
        case Mode of
            direct_key_agreement ->
                <<>>;
            key_encryption ->
                jwa:encrypt_key(Alg, CEK, JWK);
            key_wrapping ->
                jwa:wrap_key(Alg, CEK, jwk:key(JWK, {symmetric, 0}));
            key_agreement_with_key_wrapping ->
                jwa:wrap_key(Alg, CEK, AgreedKey)
        end,
    ProtectedHeader = jose_utils:encode_json(JoseHeader),
    Base64UrlProtectedHeader = jose_base64url:encode(ProtectedHeader),
    Base64UrlEncryptedKey = jose_base64url:encode(EncryptedKey),
    InitializationVector = crypto:strong_rand_bytes(jwa:iv_size(Enc)),
    Base64UrlInitializationVector = jose_base64url:encode(InitializationVector),
    M = compress(maps:get(zip, JoseHeader, undefined), Plaintext),
    AAD = additional_authentication_data(Base64UrlProtectedHeader, Base64UrlEncryptedKey, Base64UrlInitializationVector, Draft),
    {Ciphertext, AuthenticationTag} = jwa:encrypt(Enc, M, CEK, InitializationVector, AAD),
    Base64UrlCiphertext = jose_base64url:encode(Ciphertext),
    Base64UrlAuthenticationTag = jose_base64url:encode(AuthenticationTag),
    <<Base64UrlProtectedHeader/binary, $., Base64UrlEncryptedKey/binary, $., Base64UrlInitializationVector/binary, $., Base64UrlCiphertext/binary, $., Base64UrlAuthenticationTag/binary>>.

%%%===================================================================
%%% Internal functions
%%%===================================================================

decode_any(Alg, Enc, Header, EncryptedKey, Ciphertext, InitializationVector, AAD, AuthenticationTag, [JWK|Keys]) ->
    try
        Mode = jwa:key_management_mode(Alg),
        AgreedKey =
            if 
                Mode =:= direct_key_agreement; Mode =:= key_agreement_with_key_wrapping ->
                    jwa:consumer_agreed_key(Alg, JWK, Header);
                true ->
                    undefined
            end,
        CEK =
            case Mode of
                direct_key_agreement ->
                    ?assertError(<<>> =:= EncryptedKey, decrypt_failed),
                    AgreedKey;
                key_encryption ->
                    jwa:decrypt_key(Alg, EncryptedKey, JWK);
                key_wrapping ->
                    jwa:unwrap_key(Alg, EncryptedKey, jwk:key(JWK, {symmetric, 0}));
                key_agreement_with_key_wrapping ->
                    jwa:unwrap_key(Alg, EncryptedKey, AgreedKey)
            end,
        DecryptedData = jwa:decrypt(Enc, Ciphertext, CEK, InitializationVector, AAD, AuthenticationTag, Header),
        {DecryptedData, JWK}
    catch
        error:Error when Error =:= decrypt_failed; Error =:= invalid_authentication_tag; Error =:= badkey ->
            decode_any(Alg, Enc, Header, EncryptedKey, Ciphertext, InitializationVector, AAD, AuthenticationTag, Keys)
    end;
decode_any(_Alg, _Enc, _Header, _EncryptedKey, _Ciphertext, _InitializationVector, _AAD, _AuthenticationTag, []) ->
    error(decrypt_failed).

additional_authentication_data(Base64UrlProtectedHeader, Base64UrlEncryptedKey, Base64UrlInitializationVector, Draft) when Draft < 9 ->
    <<Base64UrlProtectedHeader/binary, $., Base64UrlEncryptedKey/binary, $., Base64UrlInitializationVector/binary>>;
additional_authentication_data(Base64UrlProtectedHeader, Base64UrlEncryptedKey, _Base64UrlInitializationVector, Draft) when Draft < 11 ->
    <<Base64UrlProtectedHeader/binary, $., Base64UrlEncryptedKey/binary>>;
additional_authentication_data(Base64UrlProtectedHeader, _Base64UrlEncryptedKey, _Base64UrlInitializationVector, _Draft) ->
    Base64UrlProtectedHeader.

decompress(undefined, Data) ->
    Data;
decompress(<<"DEF">>, Data) ->
    zlib:unzip(Data);
decompress(Zip, _Data) ->
    error({jwe_unsupported_zip, Zip}).

compress(undefined, Data) ->
    Data;
compress(<<"DEF">>, Data) ->
    zlib:zip(Data);
compress(Zip, _Data) ->
    error({jwe_unsupported_zip, Zip}).

