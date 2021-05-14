%% @author: Andrey
%% @date: 17.04.2015

-module(jwe_tests).

%% Include files
-include_lib("eunit/include/eunit.hrl").
-include("jose.hrl").
-include("names.hrl").

%% Exported Functions

-export([
]).

%% https://tools.ietf.org/html/draft-ietf-jose-json-web-encryption-40#appendix-A.2.1

-define(jwe_rsa1_5_a128cbc_hs256, <<"eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.UGhIOguC7IuEvf_NPVaXsGMoLOmwvc1GyqlIKOK1nN94nHPoltGRhWhw7Zx0-kFm1NJn8LE9XShH59_i8J0PH5ZZyNfGy2xGdULU7sHNF6Gp2vPLgNZ__deLKxGHZ7PcHALUzoOegEI-8E66jX2E4zyJKx-YxzZIItRzC5hlRirb6Y5Cl_p-ko3YvkkysZIFNPccxRU7qve1WYPxqbb2Yw8kZqa2rMWI5ng8OtvzlV7elprCbuPhcCdZ6XDP0_F8rkXds2vE4X-ncOIM8hAYHHi29NX0mcKiRaD0-D-ljQTP-cFPgwCp6X-nZZd9OHBv-B3oWh2TbqmScqXMR4gp_A.AxY8DCtDaGlsbGljb3RoZQ.KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY.9hH0vgRfYgPnAHOd8stkvw">>).

-define(plaintext, <<"Live long and prosper.">>).

-define(rsa_key, #{?kty => <<"RSA">>,
      ?n => <<"sXchDaQebHnPiGvyDOAT4saGEUetSyo9MKLOoWFsueri23bOdgWp4Dy1WlUzewbgBHod5pcM9H95GQRV3JDXboIRROSBigeC5yjU1hGzHHyXss8UDprecbAYxknTcQkhslANGRUZmdTOQ5qTRsLAt6BTYuyvVRdhS8exSZEy_c4gs_7svlJJQ4H9_NxsiIoLwAEk7-Q3UXERGYw_75IDrGA84-lA_-Ct4eTlXHBIY2EaV7t7LjJaynVJCpkv4LKjTTAumiGUIuQhrNhZLuF_RJLqHpM2kgWFLU7-VTdL1VbC2tejvcI2BlMkEpk1BzBZI0KQB0GaDWFLN-aEAw3vRw">>,
      ?e => <<"AQAB">>,
      ?d => <<"VFCWOqXr8nvZNyaaJLXdnNPXZKRaWCjkU5Q2egQQpTBMwhprMzWzpR8Sxq1OPThh_J6MUD8Z35wky9b8eEO0pwNS8xlh1lOFRRBoNqDIKVOku0aZb-rynq8cxjDTLZQ6Fz7jSjR1Klop-YKaUHc9GsEofQqYruPhzSA-QgajZGPbE_0ZaVDJHfyd7UUBUKunFMScbflYAAOYJqVIVwaYR5zWEEceUjNnTNo_CVSj-VvXLO5VZfCUAVLgW4dpf1SrtZjSt34YLsRarSb127reG_DUwg9Ch-KyvjT1SkHgUWRVGcyly7uvVGRSDwsXypdrNinPA4jlhoNdizK2zF2CWQ">>,
      ?p => <<"9gY2w6I6S6L0juEKsbeDAwpd9WMfgqFoeA9vEyEUuk4kLwBKcoe1x4HG68ik918hdDSE9vDQSccA3xXHOAFOPJ8R9EeIAbTi1VwBYnbTp87X-xcPWlEPkrdoUKW60tgs1aNd_Nnc9LEVVPMS390zbFxt8TN_biaBgelNgbC95sM">>,
      ?q => <<"uKlCKvKv_ZJMVcdIs5vVSU_6cPtYI1ljWytExV_skstvRSNi9r66jdd9-yBhVfuG4shsp2j7rGnIio901RBeHo6TPKWVVykPu1iYhQXw1jIABfw-MVsN-3bQ76WLdt2SDxsHs7q7zPyUyHXmps7ycZ5c72wGkUwNOjYelmkiNS0">>,
      ?dp => <<"w0kZbV63cVRvVX6yk3C8cMxo2qCM4Y8nsq1lmMSYhG4EcL6FWbX5h9yuvngs4iLEFk6eALoUS4vIWEwcL4txw9LsWH_zKI-hwoReoP77cOdSL4AVcraHawlkpyd2TWjE5evgbhWtOxnZee3cXJBkAi64Ik6jZxbvk-RR3pEhnCs">>,
      ?dq => <<"o_8V14SezckO6CNLKs_btPdFiO9_kC1DsuUTd2LAfIIVeMZ7jn1Gus_Ff7B7IVx3p5KuBGOVF8L-qifLb6nQnLysgHDh132NDioZkhH7mI7hPG-PYE_odApKdnqECHWw0J-F0JWnUd6D2B_1TvF9mXA2Qx-iGYn8OVV1Bsmp6qU">>,
      ?qi => <<"eNho5yRBEBxhGBtQRww9QirZsB66TrfFReG_CcteI1aCneT0ELGhYlRlCtUkTRclIfuEPmNsNDPbLoLqqCVznFbvdB7x-Tl-m0l_eFTj2KiqwGqE9PZB9nNTwMVvH3VRRSLWACvPnSiwP8N5Usy-WRXS-V7TbpxIhvepTfE0NNo">>
     }).

decode_rsa1_5_a128cbc_hs256_test() ->
    ?assertMatch({?plaintext, #jwe_decrypt_result{}}, jwe:decode_compact(?jwe_rsa1_5_a128cbc_hs256, ?rsa_key)).

encode_rsa1_5_a128cbc_hs256_test() ->
    JoseHeader = #{?alg => <<"RSA1_5">>, ?enc => <<"A128CBC-HS256">>},
    JWE = jwe:encode_compact(?plaintext, JoseHeader, ?rsa_key),
    ?assertMatch({?plaintext, #jwe_decrypt_result{}}, jwe:decode_compact(JWE, ?rsa_key)).

%% https://tools.ietf.org/html/draft-ietf-jose-json-web-encryption-09#appendix-A.2.1

-define(jwe_rsa1_5_a128cbc_hs256_draft9, <<"eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.nJa_uE2D0wlKz-OcwSbKFzj302xYSI-RLBM6hbVGmP4axtJQPA9S0po3s3NMkmOmkkawnfwPNjpc0mc3z79cuQWkQPFQo-mDxmogz8dxBcheaTUg3ZvpbGCXxZjDYENRWiZ5M9BiLy09BIF5mHp85QL6XED1JEZMOh-1uT1lqPDcDD79qWtrCfEJmNmfsx5fcB2PfAcVtQ0t_YmOXx5_Gu0it1nILKXLR2Ynf9mfLhEcC5LebpWyEHW6WzQ4iH9SIcIupPV1iKCzmJcPrDBJ5Fc_KMBcXBinaS__wftNywaGgfi_NSsx24LxtK6fIkejRlMBmCfxv0Tg8CtxpURigg.AxY8DCtDaGlsbGljb3RoZQ.KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY.fY2U_Hx5VcfXmipEldHhMA">>).

decode_rsa1_5_a128cbc_hs256_draft9_test() ->
    ?assertMatch({?plaintext, #jwe_decrypt_result{}}, jwe:decode_compact(?jwe_rsa1_5_a128cbc_hs256_draft9, ?rsa_key, [{jwe_draft, 9}])).

encode_rsa1_5_a128cbc_hs256_draft9_test() ->
    JoseHeader = #{?alg => <<"RSA1_5">>, ?enc => <<"A128CBC-HS256">>},
    JWE = jwe:encode_compact(?plaintext, JoseHeader, ?rsa_key, [{jwe_draft, 9}]),
    ?assertMatch({?plaintext, #jwe_decrypt_result{}}, jwe:decode_compact(JWE, ?rsa_key, [{jwe_draft, 9}])).

%% https://tools.ietf.org/html/draft-ietf-jose-json-web-encryption-07#appendix-A.2

-define(plaintext_draft7, <<"No matter where you go, there you are.">>).

-define(jwe_rsa1_5_a128cbc_hs256_draft7, <<"eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDK0hTMjU2In0.ZmnlqWgjXyqwjr7cXHys8F79anIUI6J2UWdAyRQEcGBU-KPHsePM910_RoTDGu1IW40Dn0dvcdVEjpJcPPNIbzWcMxDi131Ejeg-b8ViW5YX5oRdYdiR4gMSDDB3mbkInMNUFT-PK5CuZRnHB2rUK5fhPuF6XFqLLZCG5Q_rJm6Evex-XLcNQAJNa1-6CIU12Wj3mPExxw9vbnsQDU7B4BfmhdyiflLA7Ae5ZGoVRl3A__yLPXxRjHFhpOeDp_adx8NyejF5cz9yDKULugNsDMdlHeJQOMGVLYaSZt3KP6aWNSqFA1PHDg-10ceuTEtq_vPE4-Gtev4N4K4Eudlj4Q.AxY8DCtDaGlsbGljb3RoZQ.Rxsjg6PIExcmGSF7LnSEkDqWIKfAw1wZz2XpabV5PwQsolKwEauWYZNE9Q1hZJEZ.8LXqMd0JLGsxMaB5uoNaMpg7uUW_p40RlaZHCwMIyzk">>).

decode_rsa1_5_a128cbc_hs256_draft7_test() ->
    ?assertMatch({?plaintext_draft7, #jwe_decrypt_result{}}, jwe:decode_compact(?jwe_rsa1_5_a128cbc_hs256_draft7, ?rsa_key, [{jwe_draft, 7}])).

%% https://tools.ietf.org/html/draft-ietf-jose-json-web-encryption-40#appendix-A.3.1

-define(jwe_a128kw_a128cbc_hs256, <<"eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ.AxY8DCtDaGlsbGljb3RoZQ.KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY.U0m_YmjN04DJvceFICbCVQ">>).

-define(oct_key, #{?kty => <<"oct">>, ?k => <<"GawgguFyGrWKav7AX4VKUg">>}).

decode_a128kw_a128cbc_hs256_test() ->
    ?assertMatch({?plaintext, #jwe_decrypt_result{}}, jwe:decode_compact(?jwe_a128kw_a128cbc_hs256, ?oct_key)).
