%% @author: Andrey
%% @date: 18.04.2015

-module(jwa_props).

%% Include files
-include_lib("proper/include/proper.hrl").

%% Exported Functions

-export([
]).

%%%===================================================================
%%% API
%%%===================================================================
prop_sign_verify_es256() ->
    ?FORALL(Input, binary(), 
        begin
            {PublicKey, PrivateKey} = crypto:generate_key(ecdh, secp256r1),
            Signature = jwa:sign(<<"ES256">>, Input, #{key => PrivateKey}),
            jwa:verify(<<"ES256">>, Input, Signature, #{key => PublicKey})
        end).

prop_sign_verify_es384() ->
    ?FORALL(Input, binary(), 
        begin
            {PublicKey, PrivateKey} = crypto:generate_key(ecdh, secp384r1),
            Signature = jwa:sign(<<"ES384">>, Input, #{key => PrivateKey}),
            jwa:verify(<<"ES384">>, Input, Signature, #{key => PublicKey})
        end).

prop_sign_verify_es512() ->
    ?FORALL(Input, binary(), 
        begin
            {PublicKey, PrivateKey} = crypto:generate_key(ecdh, secp521r1),
            Signature = jwa:sign(<<"ES512">>, Input, #{key => PrivateKey}),
            jwa:verify(<<"ES512">>, Input, Signature, #{key => PublicKey})
        end).

prop_sign_verify_hs256() ->
    ?FORALL(Input, binary(), 
        ?FORALL(KeySize, integer(256, 2048),
            begin
                Key = crypto:rand_bytes(KeySize),
                Signature = jwa:sign(<<"HS256">>, Input, #{key => Key}),
                jwa:verify(<<"HS256">>, Input, Signature, #{key => Key})
            end)).

prop_sign_verify_hs384() ->
    ?FORALL(Input, binary(), 
        ?FORALL(KeySize, integer(384, 2048),
            begin
                Key = crypto:rand_bytes(KeySize),
                Signature = jwa:sign(<<"HS384">>, Input, #{key => Key}),
                jwa:verify(<<"HS384">>, Input, Signature, #{key => Key})
            end)).

prop_sign_verify_hs512() ->
    ?FORALL(Input, binary(), 
        ?FORALL(KeySize, integer(512, 2048),
            begin
                Key = crypto:rand_bytes(KeySize),
                Signature = jwa:sign(<<"HS512">>, Input, #{key => Key}),
                jwa:verify(<<"HS512">>, Input, Signature, #{key => Key})
            end)).

%%%===================================================================
%%% Internal functions
%%%===================================================================





