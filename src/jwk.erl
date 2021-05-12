%% @author: Andrey
%% @date: 17.04.2015

-module(jwk).

%% Include files
-include_lib("public_key/include/public_key.hrl").

%% Exported Functions
-export([
    set/1,
    load/1,
    load_binary/1,
    load_pem/1,
    load_pem/2,
    load_der/1,
    generate/2,
    symmetric/1,
    rsa_private/1,
    rsa_public/1,
    public/1,
    key/2,
    is_match/2,
    ec_named_curve/1
]).

-export_type([jwk/0, jwk_set/0]).

-type jwk() :: map().
-type jwk_set() :: #{keys => [jwk()]}.

%%%===================================================================
%%% API
%%%===================================================================

-spec set([jwk()]) -> jwk_set().

set(JWKs) ->
    #{keys => JWKs}.

-spec load(file:filename_all()) -> jwk().

load(Filename) ->
    {ok, Bin} = file:read_file(Filename),
    case Bin of
        <<"-----", _/binary>> -> load_pem_binary(Bin, undefined);
        _ -> der_entry_to_jwk('Certificate', Bin)
    end.    

-spec load_binary(binary()) -> jwk().

load_binary(Bin) ->
    case Bin of
        <<"-----", _/binary>> -> load_pem_binary(Bin, undefined);
        _ -> der_entry_to_jwk('Certificate', Bin)
    end.    

-spec load_pem(file:filename_all()) -> jwk().

%% @doc Genereate RSA PRIVATE KEY: openssl genrsa -out server.key 2048

load_pem(Filename) ->
    load_pem(Filename, undefined).

-spec load_pem(file:filename_all(), string() | 'undefined') -> jwk().

load_pem(Filename, Password) ->
    {ok, PemBin} = file:read_file(Filename),
    load_pem_binary(PemBin, Password).

-spec load_der(file:filename_all()) -> jwk().

load_der(Filename) ->
    {ok, Der} = file:read_file(Filename),
    der_entry_to_jwk('Certificate', Der).

generate(ec, Curve) ->
    {Public, Private} = crypto:generate_key(ecdh, Curve),
    Size = (byte_size(Public) - 1) div 2,
    SymmetricPadding = (Size - byte_size(Private)) * 8,
    PadPrivate = <<0:SymmetricPadding, Private/binary>>,
    <<4, X:Size/binary, Y:Size/binary>> = Public,
    #{kty => <<"EC">>, crv => crypto_named_curve_to_crv(Curve), x => jose_base64url:encode(X), y => jose_base64url:encode(Y), d => jose_base64url:encode(PadPrivate)}.

-spec symmetric(jwa:symmetric()) -> jwk().

symmetric(BinaryKey) ->
    #{kty => <<"oct">>, k => jose_base64url:encode(BinaryKey)}.

-spec rsa_private(jwa:rsa_private()) -> jwk().

rsa_private(RsaPrivate) ->
    rsa_private(RsaPrivate, #{}).

-spec rsa_private(jwa:rsa_private(), map()) -> jwk().

rsa_private([_,_,_] = RsaPrivate, Props) ->
    [E, N, D] = lists:map(fun jose_base64url:encode/1, map_ensure_int_as_bin(RsaPrivate)),
    Props#{kty => <<"RSA">>, n => N, e => E, d => D};
rsa_private([_,_,_,_,_,_,_,_] = RsaPrivate, Props) ->
    [E, N, D, P1, P2, E1, E2, C] = lists:map(fun jose_base64url:encode/1, map_ensure_int_as_bin(RsaPrivate)),
    Props#{kty => <<"RSA">>, n => N, e => E, d => D, p => P1, q => P2, dp => E1, dq => E2, qi => C}.

-spec rsa_public(jwa:rsa_public()) -> jwk().

rsa_public(RsaPublic) ->
    rsa_public(RsaPublic, #{}).

-spec rsa_public(jwa:rsa_public(), map()) -> jwk().

rsa_public(RsaPublic, Props) ->
    [E, N] = lists:map(fun jose_base64url:encode/1, map_ensure_int_as_bin(RsaPublic)),
    Props#{kty => <<"RSA">>, n => N, e => E}.

-spec public(jwk()) -> jwk().

public(JWK) ->
    maps:without([d, p, q, dp, dq, qi], JWK).

-spec key(jwk(), jwa:key_type()) -> jwa:key().

key(#{kty := <<"oct">>, k := BK}, {symmetric, MinSize}) ->
    Key = jose_base64url:decode(BK),
    case bit_size(Key) >= MinSize of
        true -> Key;
        false -> error(badkey)
    end;
key(#{kty := <<"RSA">>, n := BN, e := BE}, {rsa_public, MinSize}) ->
    Key = [_E, N] = lists:map(fun jose_base64url:decode/1, [BE, BN]),
    case bit_size(N) >= MinSize of
        true -> Key;
        false -> error(badkey)
    end;
key(#{kty := <<"RSA">>, n := BN, e := BE, d := BD, p := BP, q := BQ, dp := BDP, dq := BDQ, qi := BQI}, {rsa_private, MinSize}) ->
    Key = [_E, N, _D, _P, _Q, _DP, _DQ, _QI] = lists:map(fun jose_base64url:decode/1, [BE, BN, BD, BP, BQ, BDP, BDQ, BQI]),
    case bit_size(N) >= MinSize of
        true -> Key;
        false -> error(badkey)
    end;
key(#{kty := <<"RSA">>, n := BN, e := BE, d := BD}, {rsa_private, MinSize}) ->
    Key = [_E, N, _D] = lists:map(fun jose_base64url:decode/1, [BE, BN, BD]),
    case bit_size(N) >= MinSize of
        true -> Key;
        false -> error(badkey)
    end;
key(#{kty := <<"EC">>, x := BX, y := BY, crv := <<"P-256">>}, {ec_public, secp256r1}) ->
    <<4, (jose_base64url:decode(BX))/binary, (jose_base64url:decode(BY))/binary>>;
key(#{kty := <<"EC">>, x := BX, y := BY, crv := <<"P-384">>}, {ec_public, secp384r1}) ->
    <<4, (jose_base64url:decode(BX))/binary, (jose_base64url:decode(BY))/binary>>;
key(#{kty := <<"EC">>, x := BX, y := BY, crv := <<"P-521">>}, {ec_public, secp521r1}) ->
    <<4, (jose_base64url:decode(BX))/binary, (jose_base64url:decode(BY))/binary>>;
key(#{kty := <<"EC">>, d := BD, crv := <<"P-256">>}, {ec_private, secp256r1}) ->
    jose_base64url:decode(BD);
key(#{kty := <<"EC">>, d := BD, crv := <<"P-384">>}, {ec_private, secp384r1}) ->
    jose_base64url:decode(BD);
key(#{kty := <<"EC">>, d := BD, crv := <<"P-521">>}, {ec_private, secp521r1}) ->
    jose_base64url:decode(BD);
key(_, _) ->
    error(badkey).

-spec is_match(jwk(), jwa:header()) -> 'match' | 'maybe' | 'no_match'.

is_match(#{kid := KID1}, #{kid := KID2}) when KID1 =/= KID2 -> no_match;
is_match(#{x5t := X5T1}, #{x5t := X5T2}) when X5T1 =/= X5T2 -> no_match;
is_match(#{'x5t#S256' := X5TS2561}, #{'x5t#S256' := X5TS2562}) when X5TS2561 =/= X5TS2562 -> no_match;
is_match(#{kid := KID}, #{kid := KID}) -> match;
is_match(#{x5t := X5T}, #{x5t := X5T}) -> match;
is_match(#{'x5t#S256' := X5TS256}, #{'x5t#S256' := X5TS256}) -> match;
is_match(_, _) -> maybe.

ec_named_curve(JWK) ->
    #{crv := CRV} = JWK,
    crv_to_crypto_named_curve(CRV).

%%%===================================================================
%%% Internal functions
%%%===================================================================
map_ensure_int_as_bin([H|_]=List) when is_integer(H) ->
    lists:map(fun(E) -> binary:encode_unsigned(E) end, List);
map_ensure_int_as_bin(List) ->
    List.

crv_to_crypto_named_curve(<<"P-256">>) -> secp256r1;
crv_to_crypto_named_curve(<<"P-384">>) -> secp384r1;
crv_to_crypto_named_curve(<<"P-521">>) -> secp521r1;
crv_to_crypto_named_curve(CRV) -> error({jwk_unknown_crv, CRV}).

crypto_named_curve_to_crv(secp256r1) -> <<"P-256">>;
crypto_named_curve_to_crv(secp384r1) -> <<"P-384">>;
crypto_named_curve_to_crv(secp521r1) -> <<"P-521">>;
crypto_named_curve_to_crv(Curve) -> error({jwk_unknown_curve, Curve}).

load_pem_binary(PemBin, Password) ->
    Entries = public_key:pem_decode(PemBin),
    JWKs = [ pem_entry_to_jwk(Entry, Password) || Entry <- Entries ],
    lists:foldl(fun maps:merge/2, #{}, JWKs).

pem_entry_to_jwk({_Type, _Der, {_Cipher, _Salt}}, undefined) ->
    error(password_required);
pem_entry_to_jwk({Type, _Der, {_Cipher, _Salt}} = Entry, Password) ->
    der_entry_to_jwk(Type, pubkey_pem:decipher(Entry, Password));
pem_entry_to_jwk({Type, Der, not_encrypted}, _Password) ->
    der_entry_to_jwk(Type, Der).

der_entry_to_jwk('Certificate', Der) ->
    Thumbprint = crypto:hash(sha, Der),
    #'OTPCertificate'{tbsCertificate = TBSCertificate} = public_key:pkix_decode_cert(Der, otp),
    #'OTPTBSCertificate'{subject = Subject, subjectPublicKeyInfo = #'OTPSubjectPublicKeyInfo'{subjectPublicKey = PublicKey}} = TBSCertificate,
    {rdnSequence, [Attributes|_]} = Subject,
    JWK =
        case lists:keyfind(?'id-at-commonName', #'AttributeTypeAndValue'.type, Attributes) of
            #'AttributeTypeAndValue'{value = {utf8String, KID}} -> #{kid => KID};
            #'AttributeTypeAndValue'{value = {printableString, KID}} -> #{kid => list_to_binary(KID)};
            _ -> #{}
        end,
    #'RSAPublicKey'{modulus = N, publicExponent = E} = PublicKey,
    rsa_public([E, N], JWK#{x5t => jose_base64url:encode(Thumbprint)});
der_entry_to_jwk('PrivateKeyInfo', Der) ->
    case public_key:der_decode('PrivateKeyInfo', Der) of
        #'PrivateKeyInfo'{privateKey = PrivateKey} ->
            RSAKey = public_key:der_decode('RSAPrivateKey', iolist_to_binary(PrivateKey)),
            #'RSAPrivateKey'{modulus = N, publicExponent = E, privateExponent = D, prime1 = P1, prime2 = P2, exponent1 = E1, exponent2 = E2, coefficient = C} = RSAKey,
            rsa_private([E, N, D, P1, P2, E1, E2, C]);
        #'RSAPrivateKey'{modulus = N, publicExponent = E, privateExponent = D, prime1 = P1, prime2 = P2, exponent1 = E1, exponent2 = E2, coefficient = C} ->
            rsa_private([E, N, D, P1, P2, E1, E2, C])
    end;        
der_entry_to_jwk('RSAPrivateKey', Der) ->
    RSAKey = public_key:der_decode('RSAPrivateKey', Der),
    #'RSAPrivateKey'{modulus = N, publicExponent = E, privateExponent = D, prime1 = P1, prime2 = P2, exponent1 = E1, exponent2 = E2, coefficient = C} = RSAKey,
    rsa_private([E, N, D, P1, P2, E1, E2, C]).
