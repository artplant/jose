%% @author: Andrey
%% @date: 18.04.2015

-module(jose_base64url_tests).

%% Include files
-include_lib("eunit/include/eunit.hrl").

%% Exported Functions

-export([
]).

encode_empty_test() ->
    ?assertEqual(<<>>, jose_base64url:encode(<<>>)).

decode_empty_test() ->
    ?assertEqual(<<>>, jose_base64url:decode(<<>>)).

-define(test_data, <<3,236,255,224,193>>).
-define(test_base64url, <<"A-z_4ME">>).

%% https://tools.ietf.org/html/draft-ietf-jose-json-web-signature-41#appendix-C
encode_test() ->
    ?assertEqual(?test_base64url, jose_base64url:encode(?test_data)).

decode_test() ->
    ?assertEqual(?test_data, jose_base64url:decode(?test_base64url)).