%% @author: Andrey
%% @date: 17.04.2015

-module(jws_tests).

%% Include files
-include_lib("eunit/include/eunit.hrl").
-include("jose.hrl").
-include("names.hrl").

%% Exported Functions

-export([
]).

-define(payload, <<"{\"iss\":\"joe\",\r\n \"exp\":1300819380,\r\n \"http://example.com/is_root\":true}">>).

%% https://tools.ietf.org/html/draft-ietf-jose-json-web-signature-41#appendix-A.1

-define(jws_hs256, <<"eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk">>).
-define(oct_key, #{?kty => <<"oct">>, ?k => <<"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow">>}).

encode_hs256_test() ->
    JWS = jws:encode_compact(?payload, #{?alg => <<"HS256">>}, ?oct_key),
    ?assertMatch({true, ?payload, #jws_verify_result{is_verified = true}}, jws:decode_compact(JWS, ?oct_key)).

decode_hs256_test() ->
    ?assertMatch({true, ?payload, #jws_verify_result{is_verified = true}}, jws:decode_compact(?jws_hs256, ?oct_key)).

%% https://tools.ietf.org/html/draft-ietf-jose-json-web-signature-41#appendix-A.2

-define(jws_rs256, <<"eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqvhJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrBp0igcN_IoypGlUPQGe77Rw">>).

-define(rsa_key, #{?kty => <<"RSA">>,
      ?n => <<"ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddxHmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMsD1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSHSXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdVMTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ">>,
      ?e => <<"AQAB">>,
      ?d => <<"Eq5xpGnNCivDflJsRQBXHx1hdR1k6Ulwe2JZD50LpXyWPEAeP88vLNO97IjlA7_GQ5sLKMgvfTeXZx9SE-7YwVol2NXOoAJe46sui395IW_GO-pWJ1O0BkTGoVEn2bKVRUCgu-GjBVaYLU6f3l9kJfFNS3E0QbVdxzubSu3Mkqzjkn439X0M_V51gfpRLI9JYanrC4D4qAdGcopV_0ZHHzQlBjudU2QvXt4ehNYTCBr6XCLQUShb1juUO1ZdiYoFaFQT5Tw8bGUl_x_jTj3ccPDVZFD9pIuhLhBOneufuBiB4cS98l2SR_RQyGWSeWjnczT0QU91p1DhOVRuOopznQ">>,
      ?p => <<"4BzEEOtIpmVdVEZNCqS7baC4crd0pqnRH_5IB3jw3bcxGn6QLvnEtfdUdiYrqBdss1l58BQ3KhooKeQTa9AB0Hw_Py5PJdTJNPY8cQn7ouZ2KKDcmnPGBY5t7yLc1QlQ5xHdwW1VhvKn-nXqhJTBgIPgtldC-KDV5z-y2XDwGUc">>,
      ?q => <<"uQPEfgmVtjL0Uyyx88GZFF1fOunH3-7cepKmtH4pxhtCoHqpWmT8YAmZxaewHgHAjLYsp1ZSe7zFYHj7C6ul7TjeLQeZD_YwD66t62wDmpe_HlB-TnBA-njbglfIsRLtXlnDzQkv5dTltRJ11BKBBypeeF6689rjcJIDEz9RWdc">>,
      ?dp => <<"BwKfV3Akq5_MFZDFZCnW-wzl-CCo83WoZvnLQwCTeDv8uzluRSnm71I3QCLdhrqE2e9YkxvuxdBfpT_PI7Yz-FOKnu1R6HsJeDCjn12Sk3vmAktV2zb34MCdy7cpdTh_YVr7tss2u6vneTwrA86rZtu5Mbr1C1XsmvkxHQAdYo0">>,
      ?dq => <<"h_96-mK1R_7glhsum81dZxjTnYynPbZpHziZjeeHcXYsXaaMwkOlODsWa7I9xXDoRwbKgB719rrmI2oKr6N3Do9U0ajaHF-NKJnwgjMd2w9cjz3_-kyNlxAr2v4IKhGNpmM5iIgOS1VZnOZ68m6_pbLBSp3nssTdlqvd0tIiTHU">>,
      ?qi => <<"IYd7DHOhrWvxkwPQsRM2tOgrjbcrfvtQJipd-DlcxyVuuM9sQLdgjVk2oy26F0EmpScGLq2MowX7fhd_QJQ3ydy5cY7YIBi87w93IKLEdfnbJtoOPLUW0ITrJReOgo1cq9SbsxYawBgfp_gh6A5603k2-ZQwVK0JKSHuLFkuQ3U">>}).

encode_rs256_test() ->
    JWS = jws:encode_compact(?payload, #{?alg => <<"RS256">>}, ?rsa_key),
    ?assertMatch({true, ?payload, #jws_verify_result{is_verified = true}}, jws:decode_compact(JWS, ?rsa_key)).

decode_rs256_test() ->
    ?assertMatch({true, ?payload, #jws_verify_result{is_verified = true}}, jws:decode_compact(?jws_rs256, ?rsa_key)).

encode_rs384_test() ->
    JWS = jws:encode_compact(?payload, #{?alg => <<"RS384">>}, ?rsa_key),
    ?assertMatch({true, ?payload, #jws_verify_result{is_verified = true}}, jws:decode_compact(JWS, ?rsa_key)).

encode_rs512_test() ->
    JWS = jws:encode_compact(?payload, #{?alg => <<"RS512">>}, ?rsa_key),
    ?assertMatch({true, ?payload, #jws_verify_result{is_verified = true}}, jws:decode_compact(JWS, ?rsa_key)).

%% https://tools.ietf.org/html/draft-ietf-jose-json-web-signature-41#appendix-A.3

-define(jws_es256, <<"eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q">>).

-define(ec_p256_key, #{?kty => <<"EC">>,
      ?crv => <<"P-256">>,
      ?x => <<"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU">>,
      ?y => <<"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0">>,
      ?d => <<"jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI">>}).

encode_es256_test() ->
    JWS = jws:encode_compact(?payload, #{?alg => <<"ES256">>}, ?ec_p256_key),
    ?assertMatch({true, ?payload, #jws_verify_result{is_verified = true}}, jws:decode_compact(JWS, ?ec_p256_key)).

decode_es256_test() ->
    ?assertMatch({true, ?payload, #jws_verify_result{is_verified = true}}, jws:decode_compact(?jws_es256, ?ec_p256_key)).

%% https://tools.ietf.org/html/draft-ietf-jose-json-web-signature-41#appendix-A.4

-define(jws_es512,  <<"eyJhbGciOiJFUzUxMiJ9.UGF5bG9hZA.AdwMgeerwtHoh-l192l60hp9wAHZFVJbLfD_UxMi70cwnZOYaRI1bKPWROc-mZZqwqT2SI-KGDKB34XO0aw_7XdtAG8GaSwFKdCAPZgoXD2YBJZCPEX3xKpRwcdOO8KpEHwJjyqOgzDO7iKvU8vcnwNrmxYbSW9ERBXukOXolLzeO_Jn">>).

-define(ec_p521_key, #{?kty => <<"EC">>,
      ?crv => <<"P-521">>,
      ?x => <<"AekpBQ8ST8a8VcfVOTNl353vSrDCLLJXmPk06wTjxrrjcBpXp5EOnYG_NjFZ6OvLFV1jSfS9tsz4qUxcWceqwQGk">>,
      ?y => <<"ADSmRA43Z1DSNx_RvcLI87cdL07l6jQyyBXMoxVg_l2Th-x3S1WDhjDly79ajL4Kkd0AZMaZmh9ubmf63e3kyMj2">>,
      ?d => <<"AY5pb7A0UFiB3RELSD64fTLOSV_jazdF7fLYyuTw8lOfRhWg6Y6rUrPAxerEzgdRhajnu0ferB0d53vM9mE15j2C">>}).

encode_es512_test() ->
    JWS = jws:encode_compact(?payload, #{?alg => <<"ES512">>}, ?ec_p521_key),
    ?assertMatch({true, ?payload, #jws_verify_result{is_verified = true}}, jws:decode_compact(JWS, ?ec_p521_key)).

decode_es512_test() ->
    ?assertMatch({true, <<"Payload">>, #jws_verify_result{is_verified = true}}, jws:decode_compact(?jws_es512, ?ec_p521_key)).

%% https://tools.ietf.org/html/draft-ietf-jose-json-web-signature-41#appendix-A.5

-define(jws_unsecure, <<"eyJhbGciOiJub25lIn0.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.">>).

encode_unsecure_test() ->
    JWS = jws:encode_compact(?payload, #{?alg => <<"none">>}, []),
    ?assertMatch({true, ?payload, #jws_verify_result{is_verified = true}}, jws:decode_compact(JWS, [], [accept_unsecured])).

decode_unsecure_test() ->
    ?assertMatch({true, ?payload, #jws_verify_result{is_verified = true}}, jws:decode_compact(?jws_unsecure, [], [accept_unsecured])).

decode_unsecured_not_accepted_test() ->
    ?assertMatch({false, ?payload, #jws_verify_result{is_verified = false, error = unsecured_not_accepted}}, jws:decode_compact(?jws_unsecure, [])).

%% https://tools.ietf.org/html/draft-ietf-jose-json-web-signature-41#appendix-A.6

-define(jws_flattened, 
    #{<<"payload">> => <<"eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ">>,
      <<"protected">> => <<"eyJhbGciOiJFUzI1NiJ9">>,
      <<"header">> => #{kid => <<"e9bc097a-ce51-4036-9562-d2ade882db0d">>},
      <<"signature">> => <<"DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q">>}).

decode_flattened_test() ->
    ?assertMatch({true, ?payload, [#jws_verify_result{is_verified = true}]}, jws:decode_json(?jws_flattened, ?ec_p256_key)).

-define(jws_general,
    #{
        <<"payload">> => <<"eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ">>,
        <<"signatures">> => [
            #{
                <<"protected">> => <<"eyJhbGciOiJSUzI1NiJ9">>,
                <<"header">> => #{?kid => <<"2010-12-29">>},
                <<"signature">> => <<"cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqvhJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrBp0igcN_IoypGlUPQGe77Rw">>
            },
            #{
                <<"protected">> => <<"eyJhbGciOiJFUzI1NiJ9">>,
                <<"header">> => #{?kid => <<"e9bc097a-ce51-4036-9562-d2ade882db0d">>},
                <<"signature">> => <<"DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q">>
            }
        ]
     }).

decode_general_test() ->
    ?assertMatch({true, ?payload, [#jws_verify_result{is_verified = true}, #jws_verify_result{is_verified = true}]}, jws:decode_json(?jws_general, [?ec_p256_key, ?rsa_key])).

decode_general_partial_test() ->
    ?assertMatch({false, ?payload, [#jws_verify_result{is_verified = false}, #jws_verify_result{is_verified = true}]}, jws:decode_json(?jws_general, [?ec_p256_key])).
