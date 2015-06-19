-record(jws_verify_result, {
    is_verified :: boolean(),
    header :: jsx:json_term(),
    alg :: jwa:jws_alg(),
    jwk :: jwk:jwk() | 'undefined',
    error :: term()
}).

-record(jwe_decrypt_result, {
    header :: jsx:json_term(),
    jwk :: jwk:jwk(),
    alg :: jwa:jwe_alg(),
    enc :: jwa:jwe_enc()
}).