%% @author: Andrey
%% @date: 17.04.2015

-module(jwa_tests).

-export([
]).

%% Include files
-include_lib("eunit/include/eunit.hrl").
-include("names.hrl").

%% https://tools.ietf.org/html/draft-ietf-jose-json-web-signature-41#appendix-A.1

-define(hs256_input, <<"eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ">>).
-define(hs256_key, <<3,35,53,75,43,15,165,188,131,126,6,101,119,123,166,143,90,179,40,230,240,84,201,40,169,15,132,178,210,80,46,191,211,251,90,146,210,6,71,239,150,138,180,195,119,98,61,34,61,46,33,114,5,46,79,8,192,205,154,245,103,208,128,163>>).
-define(hs256_sign, <<116,24,223,180,151,153,224,37,79,250,96,125,216,173,187,186,22,212,37,77,105,214,191,240,91,88,5,88,83,132,141,121>>).

sign_hs256_test() ->
    ?assertEqual(?hs256_sign, jwa:sign(<<"HS256">>, ?hs256_input, jwk:symmetric(?hs256_key))).

verify_hs256_test() ->
    ?assert(jwa:verify(<<"HS256">>, ?hs256_input, ?hs256_sign, jwk:symmetric(?hs256_key))).

-define(aes_cbc_hs_iv, <<26,243,140,45,194,185,111,253,216,102,148,9,35,65,188,4>>).
-define(aes_cbc_hs_a, <<"The second principle of Auguste Kerckhoffs">>).
-define(aes_cbc_hs_p, <<"A cipher system must not be required to be secret, and it must be able to fall into the hands of the enemy without inconvenience">>).

%% https://tools.ietf.org/html/draft-ietf-jose-json-web-algorithms-40#appendix-B.1

-define(a128cbc_hs256_k, <<0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31>>).
-define(a128cbc_hs256_t, <<101,44,63,163,107,10,124,91,50,25,250,179,163,11,193,196>>).
-define(a128cbc_hs256_e, <<200,14,223,163,45,223,57,213,239,0,192,180,104,131,66,121,162,228,106,27,128,73,247,146,247,107,254,84,185,3,169,201,169,74,201,180,122,210,101,92,95,16,249,174,247,20,39,226,252,111,155,63,57,154,34,20,137,241,99,98,199,3,35,54,9,212,90,198,152,100,227,50,28,248,41,53,172,64,150,200,110,19,51,20,197,64,25,232,202,121,128,223,164,185,207,27,56,76,72,111,58,84,197,16,120,21,142,229,215,157,229,159,189,52,216,72,179,214,149,80,166,118,70,52,68,39,173,229,75,136,81,255,181,152,247,248,0,116,185,71,60,130,226,219>>).

encrypt_aes128cbc_hs256_test() ->
    ?assertEqual({?a128cbc_hs256_e, ?a128cbc_hs256_t}, jwa:encrypt(<<"A128CBC-HS256">>, ?aes_cbc_hs_p, ?a128cbc_hs256_k, ?aes_cbc_hs_iv, ?aes_cbc_hs_a)).

decrypt_aes128cbc_hs256_test() ->
    ?assertEqual(?aes_cbc_hs_p, jwa:decrypt(<<"A128CBC-HS256">>, ?a128cbc_hs256_e, ?a128cbc_hs256_k, ?aes_cbc_hs_iv, ?aes_cbc_hs_a, ?a128cbc_hs256_t, #{})).

%% https://datatracker.ietf.org/doc/html/draft-ietf-jose-json-web-algorithms-40#appendix-B.2

-define(a192cbc_hs384_k, <<0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47>>).
-define(a192cbc_hs384_t, <<132,144,172,14,88,148,155,254,81,135,93,115,63,147,172,32,117,22,128,57,204,199,51,215>>).
-define(a192cbc_hs384_e, <<234,101,218,107,89,230,30,219,65,155,230,45,25,113,42,229,211,3,238,181,0,82,208,223,214,105,127,119,34,76,142,219,0,13,39,155,220,20,193,7,38,84,189,48,148,66,48,198,87,190,212,202,12,159,74,132,102,242,43,34,109,23,70,33,75,248,207,194,64,10,221,159,81,38,228,121,102,63,201,11,59,237,120,122,47,15,252,191,57,4,190,42,100,29,92,33,5,191,229,145,186,226,59,29,116,73,229,50,238,246,10,154,200,187,108,107,1,211,93,73,120,123,205,87,239,72,73,39,242,128,173,201,26,192,196,231,156,123,17,239,198,0,84,227>>).

encrypt_aes192cbc_hs384_test() ->
    ?assertEqual({?a192cbc_hs384_e, ?a192cbc_hs384_t}, jwa:encrypt(<<"A192CBC-HS384">>, ?aes_cbc_hs_p, ?a192cbc_hs384_k, ?aes_cbc_hs_iv, ?aes_cbc_hs_a)).

decrypt_aes192cbc_hs384_test() ->
    ?assertEqual(?aes_cbc_hs_p, jwa:decrypt(<<"A192CBC-HS384">>, ?a192cbc_hs384_e, ?a192cbc_hs384_k, ?aes_cbc_hs_iv, ?aes_cbc_hs_a, ?a192cbc_hs384_t, #{})).

%% https://tools.ietf.org/html/draft-ietf-jose-json-web-algorithms-40#appendix-B.3

-define(a256cbc_hs512_k, <<0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,52,53,54,55,56,57,58,59,60,61,62,63>>).
-define(a256cbc_hs512_t, <<77,211,180,192,136,167,244,92,33,104,57,100,91,32,18,191,46,98,105,168,197,106,129,109,188,27,38,119,97,149,91,197>>).
-define(a256cbc_hs512_e, <<74,255,170,173,183,140,49,197,218,75,27,89,13,16,255,189,61,216,213,211,2,66,53,38,145,45,160,55,236,188,199,189,130,44,48,29,214,124,55,59,204,181,132,173,62,146,121,194,230,209,42,19,116,183,127,7,117,83,223,130,148,16,68,107,54,235,217,112,102,41,106,230,66,126,167,92,46,8,70,161,26,9,204,245,55,13,200,11,254,203,173,40,199,63,9,179,163,183,94,102,42,37,148,65,10,228,150,178,226,230,96,158,49,230,224,44,200,55,240,83,210,31,55,255,79,81,149,11,190,38,56,208,157,215,164,147,9,48,128,109,7,3,177,246>>).

encrypt_aes256cbc_hs512_test() ->
    ?assertEqual({?a256cbc_hs512_e, ?a256cbc_hs512_t}, jwa:encrypt(<<"A256CBC-HS512">>, ?aes_cbc_hs_p, ?a256cbc_hs512_k, ?aes_cbc_hs_iv, ?aes_cbc_hs_a)).

decrypt_aes256cbc_hs512_test() ->
    ?assertEqual(?aes_cbc_hs_p, jwa:decrypt(<<"A256CBC-HS512">>, ?a256cbc_hs512_e, ?a256cbc_hs512_k, ?aes_cbc_hs_iv, ?aes_cbc_hs_a, ?a256cbc_hs512_t, #{})).

%% https://tools.ietf.org/html/draft-ietf-jose-json-web-encryption-08#appendix-A.4

-define(sz_string(String), <<(byte_size(String)):32, (String)/binary>>).

concat_kdf_A128CBC_HS256_draft8_test() ->
    CMK = <<4,211,31,197,84,157,252,254,11,100,157,250,63,170,106,206,107,124,212,45,111,107,9,219,200,177,0,240,143,156,44,207>>,
    CEK = <<203,165,180,113,62,195,22,98,91,153,210,38,112,35,230,236>>,
    CIK = <<218,24,160,17,160,50,235,35,216,209,100,174,155,163,10,117,180,111,172,200,127,201,206,173,40,45,58,170,35,93,9,60>>,
    ?assertEqual(CEK, jwa:concat_kdf(CMK, 128, <<128:32, "A128CBC+HS256">>, ?sz_string(<<>>),?sz_string(<<>>), <<"Encryption">>, <<>>)),
    ?assertEqual(CIK, jwa:concat_kdf(CMK, 256, <<256:32, "A128CBC+HS256">>, ?sz_string(<<>>), ?sz_string(<<>>), <<"Integrity">>, <<>>)).

%% https://tools.ietf.org/html/draft-ietf-jose-json-web-algorithms-40#appendix-C

-define(derived_key, <<86,170,141,234,248,35,109,32,92,34,40,205,113,167,16,26>>).

concat_kdf_ecdh_es_draft40_test() ->
    Z = <<158,86,217,29,129,113,53,211,114,131,66,131,191,132,38,156,251,49,110,163,218,128,106,72,246,218,167,121,140,254,144,196>>,
    ?assertEqual(?derived_key, jwa:concat_kdf(Z, 128, ?sz_string(<<"A128GCM">>), ?sz_string(<<"Alice">>), ?sz_string(<<"Bob">>), <<128:32>>, <<>>)).

-define(header, 
    #{?alg => <<"ECDH-ES">>,
      ?enc => <<"A128GCM">>,
      ?apu => <<"QWxpY2U">>,
      ?apv => <<"Qm9i">>,
      ?epk => 
       #{?kty => <<"EC">>,
         ?crv => <<"P-256">>,
         ?x => <<"gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5SV0">>,
         ?y => <<"SLW_xSffzlPWrHEVI30DHM_4egVwt3NQqeUD7nMFpps">>
       }
     }).

-define(ec_ephemeral,
    #{?kty => <<"EC">>,
      ?crv => <<"P-256">>,
      ?x => <<"gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5SV0">>,
      ?y => <<"SLW_xSffzlPWrHEVI30DHM_4egVwt3NQqeUD7nMFpps">>,
      ?d => <<"0_NxaRPUMQoAJt50Gz8YiTr8gRTwyEaCumd-MToTmIo">>
     }).

-define(ec_private,
    #{?kty => <<"EC">>,
      ?crv => <<"P-256">>,
      ?x => <<"weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ">>,
      ?y => <<"e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck">>,
      ?d => <<"VEmDZpDXXK8p8N0Cndsxs924q6nS1RXFASRl6BfUqdw">>
     }).

consumer_key_agreement_es_test() ->
    ?assertEqual(?derived_key, jwa:consumer_agreed_key(<<"ECDH-ES">>, ?ec_private, ?header)).

producer_key_agreement_es_test() ->
    ?assertEqual(?derived_key, jwa:producer_agreed_key(<<"ECDH-ES">>, jwk:public(?ec_private), ?ec_ephemeral, ?header)).
