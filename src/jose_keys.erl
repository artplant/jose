%% @author: Andrey
%% @date: 17.04.2015

-module(jose_keys).

%% Include files
-include_lib("public_key/include/public_key.hrl").
-include("names.hrl").

%% Exported Functions

-export([
    select_keys/2
]).

-type jwks() :: jwk:jwk() | jwk:jwk_set() | [jwk:jwk()].

%%%===================================================================
%%% API
%%%===================================================================

-spec select_keys(jsx:json_term(), jwks()) -> [jwk:jwk()].

select_keys(Header, #{?keys := JWKs}) ->
    select_keys(Header, JWKs);
select_keys(Header, JWKs) when is_list(JWKs) ->
    MatchingJWKs = [ {Match, JWK} || JWK <- JWKs, Match <- [jwk:is_match(JWK, Header)], Match =/= no_match ],
    case [ JWK || {match, JWK} <- MatchingJWKs ] of
        [] ->
            [ JWK || {_, JWK} <- MatchingJWKs ];
        BestMatch ->
            BestMatch
    end;
select_keys(_Header, JWK) when is_map(JWK) ->
    [JWK].

%%%===================================================================
%%% Internal functions
%%%===================================================================





