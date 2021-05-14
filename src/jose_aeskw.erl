%% https://tools.ietf.org/html/rfc3394

-module(jose_aeskw).

-export([
    key_wrap/2,
    key_unwrap/2
]).

key_wrap(KEK, Data) ->
    A = iv(),
    Ps = list_to_tuple([ P || <<P:64>> <= Data ]),
    N = byte_size(Data) div 8,
    key_wrap_step(KEK, A, Ps, N, 1, 1, 6 * N + 1).

key_unwrap(KEK, Cipher) ->
    [ A | Cs ] = [ P || <<P:64>> <= Cipher ],
    N = byte_size(Cipher) div 8 - 1,
    key_unwrap_step(KEK, A, list_to_tuple(Cs), N, N, 6 * N).

key_wrap_step(_KEK, A, Rs, _N, _I, T, T) ->
    <<A:64, << <<R:64>> || R <- tuple_to_list(Rs) >>/binary >>;
key_wrap_step(KEK, A, Rs, N, I, T, MaxT) ->
    <<A1:64,Ri1:64>> = aes_encrypt(KEK, <<A:64, (element(I, Rs)):64>>),
    Rs1 = setelement(I, Rs, Ri1),
    I1 = case I of N -> 1; _ -> I + 1 end,
    key_wrap_step(KEK, A1 bxor T, Rs1, N, I1, T + 1, MaxT).

key_unwrap_step(_KEK, A, Rs, _N, _I, 0) ->
    case A =:= iv() of
        true -> << <<R:64>> || R <- tuple_to_list(Rs) >>;
        false -> error(decrypt_failed)
    end;
key_unwrap_step(KEK, A, Rs, N, I, T) ->
    <<A1:64,Ri1:64>> = aes_decrypt(KEK, <<(A bxor T):64, (element(I, Rs)):64>>),
    Rs1 = setelement(I, Rs, Ri1),
    I1 = case I of 1 -> N; _ -> I - 1 end,
    key_unwrap_step(KEK, A1, Rs1, N, I1, T - 1).

iv() ->
    16#a6a6a6a6a6a6a6a6.

aes_encrypt(KEK, Data) when bit_size(KEK) =:= 128 ->
    crypto:crypto_one_time(aes_128_cbc, KEK, <<0:128>>, Data, true);
aes_encrypt(KEK, Data) when bit_size(KEK) =:= 192 ->
    crypto:crypto_one_time(aes_192_cbc, KEK, <<0:128>>, Data, true);
aes_encrypt(KEK, Data) when bit_size(KEK) =:= 256 ->
    crypto:crypto_one_time(aes_256_cbc, KEK, <<0:128>>, Data, true).

aes_decrypt(KEK, Data) when bit_size(KEK) =:= 128 ->
    crypto:crypto_one_time(aes_128_cbc, KEK, <<0:128>>, Data, false);
aes_decrypt(KEK, Data) when bit_size(KEK) =:= 192 ->
    crypto:crypto_one_time(aes_192_cbc, KEK, <<0:128>>, Data, false);
aes_decrypt(KEK, Data) when bit_size(KEK) =:= 256 ->
    crypto:crypto_one_time(aes_256_cbc, KEK, <<0:128>>, Data, false).
