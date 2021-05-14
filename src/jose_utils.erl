%% @author: Andrey
%% @date: 17.04.2015

-module(jose_utils).

%% Include files

%% Exported Functions

-export([
    decode_json/1,
    encode_json/1,
    unix_timestamp/0
]).

%%%===================================================================
%%% API
%%%===================================================================
decode_json(Binary) ->
    jsx:decode(Binary, [return_maps]).

encode_json(Json) ->
    jsx:encode(Json).

unix_timestamp() ->
    {Mega, Secs, _} = os:timestamp(),
    Mega*1000000 + Secs.    

%%%===================================================================
%%% Internal functions
%%%===================================================================





