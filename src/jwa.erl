%% @author: Andrey
%% @date: 17.04.2015

% https://tools.ietf.org/html/draft-ietf-jose-json-web-algorithms-40#section-3
% JWS sign and verify algorithms:
%   +--------------+-----------------------------------+----------------+
%   | alg Param    | Digital Signature or MAC          | Implementation |
%   | Value        | Algorithm                         | Requirements   |
%   +--------------+-----------------------------------+----------------+
%   | HS256        | HMAC using SHA-256                | Required       | Implemented
%   | HS384        | HMAC using SHA-384                | Optional       | Implemented, untested
%   | HS512        | HMAC using SHA-512                | Optional       | Implemented, untested
%   | RS256        | RSASSA-PKCS-v1_5 using SHA-256    | Recommended    | Implemented
%   | RS384        | RSASSA-PKCS-v1_5 using SHA-384    | Optional       | Implemented, untested
%   | RS512        | RSASSA-PKCS-v1_5 using SHA-512    | Optional       | Implemented, untested
%   | ES256        | ECDSA using P-256 and SHA-256     | Recommended+   | Implemented
%   | ES384        | ECDSA using P-384 and SHA-384     | Optional       | Implemented, untested
%   | ES512        | ECDSA using P-521 and SHA-512     | Optional       | Implemented
%   | PS256        | RSASSA-PSS using SHA-256 and MGF1 | Optional       |
%   |              | with SHA-256                      |                |
%   | PS384        | RSASSA-PSS using SHA-384 and MGF1 | Optional       |
%   |              | with SHA-384                      |                |
%   | PS512        | RSASSA-PSS using SHA-512 and MGF1 | Optional       |
%   |              | with SHA-512                      |                |
%   | none         | No digital signature or MAC       | Optional       | Implemented
%   |              | performed                         |                |
%   +--------------+-----------------------------------+----------------+

% https://tools.ietf.org/html/draft-ietf-jose-json-web-algorithms-40#section-4
% JWE Key management algorithms
%   +--------------------+--------------------+--------+----------------+
%   | alg Param Value    | Key Management     | More   | Implementation |
%   |                    | Algorithm          | Header | Requirements   |
%   |                    |                    | Params |                |
%   +--------------------+--------------------+--------+----------------+
%   | RSA1_5             | RSAES-PKCS1-V1_5   | (none) | Recommended-   | Implemented
%   | RSA-OAEP           | RSAES OAEP using   | (none) | Recommended+   | Implemented
%   |                    | default parameters |        |                |
%   | RSA-OAEP-256       | RSAES OAEP using   | (none) | Optional       |
%   |                    | SHA-256 and MGF1   |        |                |
%   |                    | with SHA-256       |        |                |
%   | A128KW             | AES Key Wrap with  | (none) | Recommended    | Implemented
%   |                    | default initial    |        |                |
%   |                    | value using 128    |        |                |
%   |                    | bit key            |        |                |
%   | A192KW             | AES Key Wrap with  | (none) | Optional       | Implemented, untested
%   |                    | default initial    |        |                |
%   |                    | value using 192    |        |                |
%   |                    | bit key            |        |                |
%   | A256KW             | AES Key Wrap with  | (none) | Recommended    | Implemented, untested
%   |                    | default initial    |        |                |
%   |                    | value using 256    |        |                |
%   |                    | bit key            |        |                |
%   | dir                | Direct use of a    | (none) | Recommended    | Implemented
%   |                    | shared symmetric   |        |                |
%   |                    | key as the CEK     |        |                |
%   | ECDH-ES            | Elliptic Curve     | "epk", | Recommended+   | Implemented
%   |                    | Diffie-Hellman     | "apu", |                |
%   |                    | Ephemeral Static   | "apv"  |                |
%   |                    | key agreement      |        |                |
%   |                    | using Concat KDF   |        |                |
%   | ECDH-ES+A128KW     | ECDH-ES using      | "epk", | Recommended    | Implemented, untested
%   |                    | Concat KDF and CEK | "apu", |                |
%   |                    | wrapped with       | "apv"  |                |
%   |                    | "A128KW"           |        |                |
%   | ECDH-ES+A192KW     | ECDH-ES using      | "epk", | Optional       | Implemented, untested
%   |                    | Concat KDF and CEK | "apu", |                |
%   |                    | wrapped with       | "apv"  |                |
%   |                    | "A192KW"           |        |                |
%   | ECDH-ES+A256KW     | ECDH-ES using      | "epk", | Recommended    | Implemented, untested
%   |                    | Concat KDF and CEK | "apu", |                |
%   |                    | wrapped with       | "apv"  |                |
%   |                    | "A256KW"           |        |                |
%   | A128GCMKW          | Key wrapping with  | "iv",  | Optional       |
%   |                    | AES GCM using 128  | "tag"  |                |
%   |                    | bit key            |        |                |
%   | A192GCMKW          | Key wrapping with  | "iv",  | Optional       |
%   |                    | AES GCM using 192  | "tag"  |                |
%   |                    | bit key            |        |                |
%   | A256GCMKW          | Key wrapping with  | "iv",  | Optional       |
%   |                    | AES GCM using 256  | "tag"  |                |
%   |                    | bit key            |        |                |
%   | PBES2-HS256+A128KW | PBES2 with HMAC    | "p2s", | Optional       |
%   |                    | SHA-256 and        | "p2c"  |                |
%   |                    | "A128KW" wrapping  |        |                |
%   | PBES2-HS384+A192KW | PBES2 with HMAC    | "p2s", | Optional       |
%   |                    | SHA-384 and        | "p2c"  |                |
%   |                    | "A192KW" wrapping  |        |                |
%   | PBES2-HS512+A256KW | PBES2 with HMAC    | "p2s", | Optional       |
%   |                    | SHA-512 and        | "p2c"  |                |
%   |                    | "A256KW" wrapping  |        |                |
%   +--------------------+--------------------+--------+----------------+

% https://tools.ietf.org/html/draft-ietf-jose-json-web-algorithms-40#section-5
% JWE encryption algorithms
%   +---------------+----------------------------------+----------------+
%   | enc Param     | Content Encryption Algorithm     | Implementation |
%   | Value         |                                  | Requirements   |
%   +---------------+----------------------------------+----------------+
%   | A128CBC-HS256 | AES_128_CBC_HMAC_SHA_256         | Required       | Implemented
%   |               | authenticated encryption         |                |
%   |               | algorithm, as defined in         |                |
%   |               | Section 5.2.3                    |                |
%   | A192CBC-HS384 | AES_192_CBC_HMAC_SHA_384         | Optional       | Implemented
%   |               | authenticated encryption         |                |
%   |               | algorithm, as defined in         |                |
%   |               | Section 5.2.4                    |                |
%   | A256CBC-HS512 | AES_256_CBC_HMAC_SHA_512         | Required       | Implemented
%   |               | authenticated encryption         |                |
%   |               | algorithm, as defined in         |                |
%   |               | Section 5.2.5                    |                |
%   | A128GCM       | AES GCM using 128 bit key        | Recommended    |
%   | A192GCM       | AES GCM using 192 bit key        | Optional       |
%   | A256GCM       | AES GCM using 256 bit key        | Recommended    |
%   +---------------+----------------------------------+----------------+

-module(jwa).

%% Include files
-include_lib("public_key/include/public_key.hrl").
-include("names.hrl").
-include("assert.hrl").

%% Exported Functions

-export([
    sign/3,
    verify/4,
    key_management_mode/1,
    producer_agreed_key/4,
    consumer_agreed_key/3,
    encrypt_key/3,
    decrypt_key/3,
    cek_size/1,
    iv_size/1,
    encrypt/5,
    decrypt/7,
    concat_kdf/7,
    pkcs7_pad/2,
    pkcs7_unpad/1,
    wrap_key/3,
    unwrap_key/3
]).

-export_type([key_type/0, key/0, symmetric/0, rsa_private/0, rsa_public/0, ec_private/0, ec_public/0, header/0]).
-export_type([jws_alg/0, jwe_alg/0, jwe_enc/0]).

-type key_type() :: 
    {'symmetric', pos_integer()} | 
    {'rsa_public', pos_integer()} | {'rsa_private', pos_integer()} | 
    {'ec_public', ec_curve_name()} | {'ec_private', ec_curve_name()}.

-type ec_curve_name() :: 'secp256r1' | 'secp384r1' | 'secp521r1'.

-type key() :: symmetric() | rsa_public() | rsa_private() | ec_public() | ec_private().

-type symmetric() :: binary().
-type rsa_private() :: [binary()] | [integer()].
-type rsa_public() :: [binary()] | [integer()].
-type ec_private() :: binary().
-type ec_public() :: binary().
    
-type jws_alg() :: binary().
-type jwe_alg() :: binary().
-type jwe_enc() :: binary().

-type header() :: map().

-type key_management_mode() :: 'key_encryption' | 'direct_key_agreement'.

-define(sz_string(String), <<(byte_size(String)):32, (String)/binary>>).

%%%===================================================================
%%% API
%%%===================================================================

-spec sign(jws_alg(), binary(), jwk:jwk() | 'undefined') -> binary().

sign(<<"none">>, _Input, _JWK) ->
    <<>>;
sign(<<"HS256">>, Input, JWK) ->
    Key = jwk:key(JWK, {symmetric, 256}),
    crypto:mac(hmac, sha256, Key, Input);
sign(<<"HS384">>, Input, JWK) ->
    Key = jwk:key(JWK, {symmetric, 384}),
    crypto:mac(hmac, sha384, Key, Input);
sign(<<"HS512">>, Input, JWK) ->
    Key = jwk:key(JWK, {symmetric, 512}),
    crypto:mac(hmac, sha512, Key, Input);
sign(<<"RS256">>, Input, JWK) ->
    Key = jwk:key(JWK, {rsa_private, 2048}),
    crypto:sign(rsa, sha256, Input, Key);
sign(<<"RS384">>, Input, JWK) ->
    Key = jwk:key(JWK, {rsa_private, 2048}),
    crypto:sign(rsa, sha384, Input, Key);
sign(<<"RS512">>, Input, JWK) ->
    Key = jwk:key(JWK, {rsa_private, 2048}),
    crypto:sign(rsa, sha512, Input, Key);
sign(<<"ES256">>, Input, JWK) ->
    Key = jwk:key(JWK, {ec_private, secp256r1}),
    Asn1Signature = crypto:sign(ecdsa, sha256, Input, [Key, secp256r1]),
    #'ECDSA-Sig-Value'{r = R, s = S} = public_key:der_decode('ECDSA-Sig-Value', Asn1Signature),
    <<R:256,S:256>>;
sign(<<"ES384">>, Input, JWK) ->
    Key = jwk:key(JWK, {ec_private, secp384r1}),
    Asn1Signature = crypto:sign(ecdsa, sha384, Input, [Key, secp384r1]),
    #'ECDSA-Sig-Value'{r = R, s = S} = public_key:der_decode('ECDSA-Sig-Value', Asn1Signature),
    <<R:384,S:384>>;
sign(<<"ES512">>, Input, JWK) ->
    Key = jwk:key(JWK, {ec_private, secp521r1}),
    Asn1Signature = crypto:sign(ecdsa, sha512, Input, [Key, secp521r1]),
    #'ECDSA-Sig-Value'{r = R, s = S} = public_key:der_decode('ECDSA-Sig-Value', Asn1Signature),
    <<R:528,S:528>>;
sign(Alg, _Input, _JWK) ->
    error({unsupported_alg, Alg}).

-spec verify(jws_alg(), binary(), binary(), key()) -> boolean().

verify(<<"none">>, _Input, Signature, _JWK) ->
    Signature =:= <<>>;
verify(<<"HS256">>, Input, Signature, JWK) ->
    Key = jwk:key(JWK, {symmetric, 256}),
    crypto:mac(hmac, sha256, Key, Input) =:= Signature;
verify(<<"HS384">>, Input, Signature, JWK) ->
    Key = jwk:key(JWK, {symmetric, 384}),
    crypto:mac(hmac, sha384, Key, Input) =:= Signature;
verify(<<"HS512">>, Input, Signature, JWK) ->
    Key = jwk:key(JWK, {symmetric, 512}),
    crypto:mac(hmac, sha512, Key, Input) =:= Signature;
verify(<<"RS256">>, Input, Signature, JWK) ->
    Key = jwk:key(JWK, {rsa_public, 2048}),
    crypto:verify(rsa, sha256, Input, Signature, Key);
verify(<<"RS384">>, Input, Signature, JWK) ->
    Key = jwk:key(JWK, {rsa_public, 2048}),
    crypto:verify(rsa, sha384, Input, Signature, Key);
verify(<<"RS512">>, Input, Signature, JWK) ->
    Key = jwk:key(JWK, {rsa_public, 2048}),
    crypto:verify(rsa, sha512, Input, Signature, Key);
verify(<<"ES256">>, Input, Signature, JWK) ->
    Key = jwk:key(JWK, {ec_public, secp256r1}),
    <<R:32/binary,S:32/binary>> = Signature,
    Asn1Signature = public_key:der_encode('ECDSA-Sig-Value', #'ECDSA-Sig-Value'{r = binary:decode_unsigned(R), s = binary:decode_unsigned(S)}),
    crypto:verify(ecdsa, sha256, Input, Asn1Signature, [Key, secp256r1]);
verify(<<"ES384">>, Input, Signature, JWK) ->
    Key = jwk:key(JWK, {ec_public, secp384r1}),
    <<R:48/binary,S:48/binary>> = Signature,
    Asn1Signature = public_key:der_encode('ECDSA-Sig-Value', #'ECDSA-Sig-Value'{r = binary:decode_unsigned(R), s = binary:decode_unsigned(S)}),
    crypto:verify(ecdsa, sha384, Input, Asn1Signature, [Key, secp384r1]);
verify(<<"ES512">>, Input, Signature, JWK) ->
    Key = jwk:key(JWK, {ec_public, secp521r1}),
    <<R:66/binary,S:66/binary>> = Signature,
    Asn1Signature = public_key:der_encode('ECDSA-Sig-Value', #'ECDSA-Sig-Value'{r = binary:decode_unsigned(R), s = binary:decode_unsigned(S)}),
    crypto:verify(ecdsa, sha512, Input, Asn1Signature, [Key, secp521r1]);
verify(Alg, _Input, _Signature, _JWK) ->
    error({unsupported_alg, Alg}).

-spec key_management_mode(jwe_alg()) -> key_management_mode().

key_management_mode(<<"RSA1_5">>) -> key_encryption;
key_management_mode(<<"RSA-OAEP">>) -> key_encryption;
key_management_mode(<<"A128KW">>) -> key_wrapping;
key_management_mode(<<"A192KW">>) -> key_wrapping;
key_management_mode(<<"A256KW">>) -> key_wrapping;
key_management_mode(<<"ECDH-ES">>) -> direct_key_agreement;
key_management_mode(<<"ECDH-ES+A128KW">>) -> key_agreement_with_key_wrapping;
key_management_mode(<<"ECDH-ES+A192KW">>) -> key_agreement_with_key_wrapping;
key_management_mode(<<"ECDH-ES+A256KW">>) -> key_agreement_with_key_wrapping;
key_management_mode(<<"dir">>) -> direct_key_agreement;
key_management_mode(Alg) -> error({unsupported_alg, Alg}).

producer_agreed_key(<<"ECDH-ES">>, JWK, EcPrivateEphemeralKey, Header) ->
    ecdh_es_agreed_key(maps:get(?enc, Header), 128, Header, JWK, EcPrivateEphemeralKey);
producer_agreed_key(<<"ECDH-ES+A128KW">> = Alg, JWK, EcPrivateEphemeralKey, Header) ->
    ecdh_es_agreed_key(Alg, 128, Header, JWK, EcPrivateEphemeralKey);
producer_agreed_key(<<"ECDH-ES+A192KW">> = Alg, JWK, EcPrivateEphemeralKey, Header) ->
    ecdh_es_agreed_key(Alg, 192, Header, JWK, EcPrivateEphemeralKey);
producer_agreed_key(<<"ECDH-ES+A256KW">> = Alg, JWK, EcPrivateEphemeralKey, Header) ->
    ecdh_es_agreed_key(Alg, 256, Header, JWK, EcPrivateEphemeralKey);
producer_agreed_key(<<"dir">>, SymmetricKey, _, _Header) ->
    SymmetricKey;
producer_agreed_key(Alg, _Key, _, _Header) ->
    error({unsupported_alg, Alg}).

consumer_agreed_key(<<"ECDH-ES">>, JWK, Header) ->
    ecdh_es_agreed_key(maps:get(?enc, Header), 128, Header, maps:get(?epk, Header), JWK);
consumer_agreed_key(<<"ECDH-ES+A128KW">> = Alg, JWK, Header) ->
    ecdh_es_agreed_key(Alg, 128, Header, maps:get(?epk, Header), JWK);
consumer_agreed_key(<<"ECDH-ES+A192KW">> = Alg, JWK, Header) ->
    ecdh_es_agreed_key(Alg, 192, Header, maps:get(?epk, Header), JWK);
consumer_agreed_key(<<"ECDH-ES+A256KW">> = Alg, JWK, Header) ->
    ecdh_es_agreed_key(Alg, 256, Header, maps:get(?epk, Header), JWK);
consumer_agreed_key(<<"dir">>, SymmetricKey, _Header) ->
    SymmetricKey;
consumer_agreed_key(Alg, _Key, _Header) ->
    error({unsupported_alg, Alg}).

encrypt_key(<<"RSA1_5">>, CEK, JWK) ->
    RSA = jwk:key(JWK, {rsa_public, 2048}),
    crypto:public_encrypt(rsa, CEK, RSA, rsa_pkcs1_padding);
encrypt_key(<<"RSA-OAEP">>, CEK, JWK) ->
    RSA = jwk:key(JWK, {rsa_public, 2048}),
    crypto:public_encrypt(rsa, CEK, RSA, rsa_pkcs1_oaep_padding);
encrypt_key(Alg, _CEK, _JWK) ->
    error({unsupported_alg, Alg}).

wrap_key(<<"A128KW">>, CEK, KEK) ->
    ?assertError(byte_size(KEK) =:= 128, badkey),
    jose_aeskw:key_wrap(KEK, CEK);
wrap_key(<<"A192KW">>, CEK, KEK) ->
    ?assertError(byte_size(KEK) =:= 192, badkey),
    jose_aeskw:key_wrap(KEK, CEK);
wrap_key(<<"A256KW">>, CEK, KEK) ->
    ?assertError(byte_size(KEK) =:= 256, badkey),
    jose_aeskw:key_wrap(KEK, CEK);
wrap_key(Alg, _CEK, _KEK) ->
    error({unsupported_alg, Alg}).

decrypt_key(<<"RSA1_5">>, EncryptedKey, JWK) ->
    RSA = jwk:key(JWK, {rsa_private, 2048}),
    crypto:private_decrypt(rsa, EncryptedKey, RSA, rsa_pkcs1_padding);
decrypt_key(<<"RSA-OAEP">>, EncryptedKey, JWK) ->
    RSA = jwk:key(JWK, {rsa_private, 2048}),
    crypto:private_decrypt(rsa, EncryptedKey, RSA, rsa_pkcs1_oaep_padding);
decrypt_key(Alg, _EncryptedKey, _Key) ->
    error({unsupported_alg, Alg}).

unwrap_key(<<"A128KW">>, EncryptedKey, KEK) ->
    ?assertError(bit_size(KEK) =:= 128, badkey),
    jose_aeskw:key_unwrap(KEK, EncryptedKey);
unwrap_key(<<"A192KW">>, EncryptedKey, KEK) ->
    ?assertError(bit_size(KEK) =:= 192, badkey),
    jose_aeskw:key_unwrap(KEK, EncryptedKey);
unwrap_key(<<"A256KW">>, EncryptedKey, KEK) ->
    ?assertError(bit_size(KEK) =:= 256, badkey),
    jose_aeskw:key_unwrap(KEK, EncryptedKey);
unwrap_key(Alg, _EncryptedKey, _KEK) ->
    error({unsupported_alg, Alg}).

-spec cek_size(jwe_enc()) -> pos_integer().

cek_size(<<"A128CBC-HS256">>) -> 32;
cek_size(<<"A192CBC-HS384">>) -> 48;
cek_size(<<"A256CBC-HS512">>) -> 64;
cek_size(Enc) -> error({unsupported_enc, Enc}).

-spec iv_size(jwe_enc()) -> pos_integer().

iv_size(<<"A128CBC-HS256">>) -> 16;
iv_size(<<"A182CBC-HS384">>) -> 16;
iv_size(<<"A256CBC-HS512">>) -> 16;
iv_size(Enc) -> error({unsupported_enc, Enc}).

-spec encrypt(jwe_enc(), binary(), binary(), binary(), binary()) -> {binary(), binary()}.

encrypt(<<"A128CBC-HS256">>, Plaintext, CEK, IV, AAD) ->
    <<MAC_KEY:16/binary, ENC_KEY:16/binary>> = CEK,
    AL = bit_size(AAD),
    Ciphertext = crypto:crypto_one_time(aes_128_cbc, ENC_KEY, IV, pkcs7_pad(Plaintext, 16), true),
    IntegrityData = <<AAD/binary, IV/binary, Ciphertext/binary, AL:8/big-unsigned-integer-unit:8>>,
    <<HMAC:16/binary, _/binary>> = crypto:mac(hmac, sha256, MAC_KEY, IntegrityData),
    {Ciphertext, HMAC};
encrypt(<<"A192CBC-HS384">>, Plaintext, CEK, IV, AAD) ->
    <<MAC_KEY:24/binary, ENC_KEY:24/binary>> = CEK,
    AL = bit_size(AAD),
    Ciphertext = crypto:crypto_one_time(aes_192_cbc, ENC_KEY, IV, pkcs7_pad(Plaintext, 16), true),
    IntegrityData = <<AAD/binary, IV/binary, Ciphertext/binary, AL:8/big-unsigned-integer-unit:8>>,
    <<HMAC:24/binary, _/binary>> = crypto:mac(hmac, sha384, MAC_KEY, IntegrityData),
    {Ciphertext, HMAC};
encrypt(<<"A256CBC-HS512">>, Plaintext, CEK, IV, AAD) ->
    <<MAC_KEY:32/binary, ENC_KEY:32/binary>> = CEK,
    AL = bit_size(AAD),
    Ciphertext = crypto:crypto_one_time(aes_256_cbc, ENC_KEY, IV, pkcs7_pad(Plaintext, 16), true),
    IntegrityData = <<AAD/binary, IV/binary, Ciphertext/binary, AL:8/big-unsigned-integer-unit:8>>,
    <<HMAC:32/binary, _/binary>> = crypto:mac(hmac, sha512, MAC_KEY, IntegrityData),
    {Ciphertext, HMAC};
encrypt(Enc, _, _, _, _) ->
    error({unsupported_enc, Enc}).

-spec decrypt(jwe_enc(), binary(), binary(), binary(), binary(), binary(), jsx:json_term()) -> binary().

decrypt(<<"A128CBC-HS256">>, Ciphertext, CEK, IV, AAD, Tag, _Header) ->
    <<MAC_KEY:16/binary, ENC_KEY:16/binary>> = CEK,
    AL = bit_size(AAD),
    IntegrityData = <<AAD/binary, IV/binary, Ciphertext/binary, AL:8/big-unsigned-integer-unit:8>>,
    <<HMAC:16/binary, _/binary>> = crypto:mac(hmac, sha256, MAC_KEY, IntegrityData),
    case HMAC =:= Tag of
        true -> ok;
        false -> error(invalid_authentication_tag)
    end,
    pkcs7_unpad(crypto:crypto_one_time(aes_128_cbc, ENC_KEY, IV, Ciphertext, false));
decrypt(<<"A192CBC-HS384">>, Ciphertext, CEK, IV, AAD, Tag, _Header) ->
    <<MAC_KEY:24/binary, ENC_KEY:24/binary>> = CEK,
    AL = bit_size(AAD),
    IntegrityData = <<AAD/binary, IV/binary, Ciphertext/binary, AL:8/big-unsigned-integer-unit:8>>,
    <<HMAC:24/binary, _/binary>> = crypto:mac(hmac, sha384, MAC_KEY, IntegrityData),
    case HMAC =:= Tag of
        true -> ok;
        false -> error(invalid_authentication_tag)
    end,
    pkcs7_unpad(crypto:crypto_one_time(aes_192_cbc, ENC_KEY, IV, Ciphertext, false));
decrypt(<<"A256CBC-HS512">>, Ciphertext, CEK, IV, AAD, Tag, _Header) ->
    <<MAC_KEY:32/binary, ENC_KEY:32/binary>> = CEK,
    AL = bit_size(AAD),
    IntegrityData = <<AAD/binary, IV/binary, Ciphertext/binary, AL:8/big-unsigned-integer-unit:8>>,
    <<HMAC:32/binary, _/binary>> = crypto:mac(hmac, sha512, MAC_KEY, IntegrityData),
    case HMAC =:= Tag of
        true -> ok;
        false -> error(invalid_authentication_tag)
    end,
    pkcs7_unpad(crypto:crypto_one_time(aes_256_cbc, ENC_KEY, IV, Ciphertext, false));
decrypt(<<"A128CBC+HS256">>, Ciphertext, CMK, IV, AAD, Tag, Header) ->
    Epu = jose_base64url:decode(maps:get(?epu, Header, <<>>)),
    Epv = jose_base64url:decode(maps:get(?epv, Header, <<>>)),
    CEK = concat_kdf(CMK, 128, <<128:32, "A128CBC+HS256">>, ?sz_string(Epu), ?sz_string(Epv), <<"Encryption">>, <<>>),
    CIK = concat_kdf(CMK, 256, <<256:32, "A128CBC+HS256">>, ?sz_string(Epu), ?sz_string(Epv), <<"Integrity">>, <<>>),
    IntegrityData = <<AAD/binary, $., (jose_base64url:encode(Ciphertext))/binary>>,
    <<HMAC:32/binary, _/binary>> = crypto:mac(hmac, sha256, CIK, IntegrityData),
    case HMAC =:= Tag of
        true -> ok;
        false -> error(invalid_authentication_tag)
    end,
    pkcs7_unpad(crypto:crypto_one_time(aes_128_cbc, CEK, IV, Ciphertext, false));
decrypt(Enc, _, _, _, _, _, _) ->
    error({unsupported_enc, Enc}).

-spec concat_kdf(binary(), pos_integer(), binary(), binary(), binary(), binary(), binary()) -> binary().

%% https://tools.ietf.org/html/draft-ietf-jose-json-web-encryption-08#appendix-A.4
concat_kdf(Z, KeyDataLen, AlgorithmID, PartyUInfo, PartyVInfo, SuppPubInfo, SuppPrivInfo) ->
    Input = <<0,0,0,1, Z/binary, AlgorithmID/binary, PartyUInfo/binary, PartyVInfo/binary, SuppPubInfo/binary, SuppPrivInfo/binary>>,
    binary:part(crypto:hash(sha256, Input), 0, KeyDataLen div 8).

-spec pkcs7_pad(binary(), byte()) -> binary().

pkcs7_pad(Data, BlockSize) ->
    Padding = BlockSize - byte_size(Data) rem BlockSize,
    BinPadding = << <<Padding>> || _ <- lists:seq(1, Padding) >>,
    <<Data/binary, BinPadding/binary>>.

-spec pkcs7_unpad(binary()) -> binary().

pkcs7_unpad(Data) ->
    Size = byte_size(Data) - binary:last(Data),
    binary:part(Data, 0, Size).

%%%===================================================================
%%% Internal functions
%%%===================================================================

ecdh_es_agreed_key(Alg, KeyLen, Header, Public, Private) ->
    Apu = jose_base64url:decode(maps:get(?apu, Header, <<>>)),
    Apv = jose_base64url:decode(maps:get(?apv, Header, <<>>)),
    Curve = jwk:ec_named_curve(Public),
    EcPublic = jwk:key(Public, {ec_public, Curve}),
    Z = crypto:compute_key(ecdh, EcPublic, jwk:key(Private, {ec_private, Curve}), Curve),
    jwa:concat_kdf(Z, KeyLen, ?sz_string(Alg), ?sz_string(Apu), ?sz_string(Apv), <<KeyLen:32>>, <<>>).

