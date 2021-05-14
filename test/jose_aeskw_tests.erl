%% @author: Andrey
%% @date: 28.04.2015

-module(jose_aeskw_tests).

%% Include files
-include_lib("eunit/include/eunit.hrl").

%% Exported Functions

-export([
]).

-define(KEK128, <<16#000102030405060708090A0B0C0D0E0F:128>>).
-define(KEK192, <<16#00102030405060708090A0B0C0D0E0F1011121314151617:192>>).
-define(KEK256, <<16#000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F:256>>).

-define(data128, <<16#00112233445566778899AABBCCDDEEFF:128>>).
-define(data192, <<16#00112233445566778899AABBCCDDEEFF0001020304050607:192>>).
-define(data256, <<16#00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F:256>>).

-define(cipher128_128, <<16#1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5:192>>).
-define(cipher128_192, <<16#96778B25AE6CA435F92B5B97C050AED2468AB8A17AD84E5D:192>>).
-define(cipher128_256, <<16#64E8C3F9CE0F5BA263E9777905818A2A93C8191E7D6E8AE7:192>>).
-define(cipher192_192, <<16#031D33264E15D33268F24EC260743EDCE1C6C7DDEE725A936BA814915C6762D2:256>>).
-define(cipher192_256, <<16#A8F9BC1612C68B3FF6E6F4FBE30E71E4769C8B80A32CB8958CD5D17D6B254DA1:256>>).
-define(cipher256_256, <<16#28C9F404C4B810F4CBCCB35CFB87F8263F5786E2D80ED326CBC7F0E71A99F43BFB988B9B7A02DD21:320>>).

key_wrap_128_128_test() ->
    ?assertEqual(?cipher128_128, jose_aeskw:key_wrap(?KEK128, ?data128)).

key_unwrap_128_128_test() ->
    ?assertEqual(?data128, jose_aeskw:key_unwrap(?KEK128, ?cipher128_128)).

key_wrap_128_192_test() ->
    ?assertEqual(?cipher128_192, jose_aeskw:key_wrap(?KEK192, ?data128)).

key_unwrap_128_192_test() ->
    ?assertEqual(?data128, jose_aeskw:key_unwrap(?KEK192, ?cipher128_192)).

key_wrap_128_256_test() ->
    ?assertEqual(?cipher128_256, jose_aeskw:key_wrap(?KEK256, ?data128)).

key_unwrap_128_256_test() ->
    ?assertEqual(?data128, jose_aeskw:key_unwrap(?KEK256, ?cipher128_256)).

key_wrap_192_192_test() ->
    ?assertEqual(?cipher192_192, jose_aeskw:key_wrap(?KEK192, ?data192)).

key_unwrap_192_192_test() ->
    ?assertEqual(?data192, jose_aeskw:key_unwrap(?KEK192, ?cipher192_192)).

key_wrap_192_256_test() ->
    ?assertEqual(?cipher192_256, jose_aeskw:key_wrap(?KEK256, ?data192)).

key_unwrap_192_256_test() ->
    ?assertEqual(?data192, jose_aeskw:key_unwrap(?KEK256, ?cipher192_256)).

key_wrap_256_256_test() ->
    ?assertEqual(?cipher256_256, jose_aeskw:key_wrap(?KEK256, ?data256)).

key_unwrap_256_256_test() ->
    ?assertEqual(?data256, jose_aeskw:key_unwrap(?KEK256, ?cipher256_256)).

