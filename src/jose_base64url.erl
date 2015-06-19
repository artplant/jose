%% @author: Andrey
%% @date: 18.04.2015

-module(jose_base64url).

%% Include files

%% Exported Functions

-export([
    encode/1,
    decode/1
]).

%%%===================================================================
%%% API
%%%===================================================================

-spec encode(binary()) -> binary().

%% https://tools.ietf.org/html/draft-ietf-jose-json-web-signature-41#appendix-C
encode(Data) ->
    Base64 = base64:encode(Data),
    << <<(encode_byte(B)):8>> || <<B:8>> <= Base64, B =/= $= >>.

encode_byte($+) -> $-;
encode_byte($/) -> $_;
encode_byte(B) -> B.

-spec decode(binary()) -> binary().

%% https://tools.ietf.org/html/draft-ietf-jose-json-web-signature-41#appendix-C
decode(Data) ->
    Base64 = pad(<< <<(decode_byte(B)):8>> || <<B:8>> <= Data >>, byte_size(Data) rem 4),
    base64:decode(Base64).

decode_byte($-) -> $+;
decode_byte($_) -> $/;
decode_byte(B) -> B.

pad(Data, 0) -> Data;
pad(Data, 2) -> <<Data/binary, "==">>;
pad(Data, 3) -> <<Data/binary, "=">>.


%%%===================================================================
%%% Internal functions
%%%===================================================================





