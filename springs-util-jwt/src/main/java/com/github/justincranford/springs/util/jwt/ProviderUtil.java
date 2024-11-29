package com.github.justincranford.springs.util.jwt;

import lombok.AccessLevel;
import lombok.NoArgsConstructor;

import java.security.Provider;
import java.security.Security;

@NoArgsConstructor(access=AccessLevel.PRIVATE)
final class ProviderUtil {
    static final Provider ED_KEY_PAIR_GENERATOR_PROVIDER   = Security.getProvider("SunEC");      // alg: EdDSA, Ed25519, Ed448
    static final Provider EC_KEY_PAIR_GENERATOR_PROVIDER   = Security.getProvider("SunEC");      // alg: ES256, ES256K, ES384, ES512
    static final Provider RSA_KEY_PAIR_GENERATOR_PROVIDER  = Security.getProvider("SunRsaSign"); // alg: PS256, PS384, PS512, RS256, RS384, RS512
    static final Provider HMAC_KEY_GENERATOR_PROVIDER      = Security.getProvider("SunJCE");     // alg: HS256, HS384, HS512
    static final Provider AES_KEY_GENERATOR_PROVIDER       = Security.getProvider("SunJCE");     // alg: A128GCMKW, A192GCMKW, A256GCMKW, A128KW, A192KW, A256KW

    static final Provider ED_SIGN_VERIFY_PROVIDER      = Security.getProvider("SunEC");      // alg: EdDSA, Ed25519, Ed448
    static final Provider EC_SIGN_VERIFY_PROVIDER      = Security.getProvider("SunEC");      // alg: ES256, ES256K, ES384, ES512
    static final Provider RSA_SIGN_VERIFY_PROVIDER     = Security.getProvider("SunRsaSign"); // alg: PS256, PS384, PS512, RS256, RS384, RS512
    static final Provider HMAC_SIGN_VERIFY_PROVIDER    = Security.getProvider("SunJCE");     // alg: HS256, HS384, HS512
    static final Provider EC_ENCRYPT_DECRYPT_PROVIDER  = Security.getProvider("SunEC");      // alg: ES256, ES256K, ES384, ES512
    static final Provider RSA_ENCRYPT_DECRYPT_PROVIDER = Security.getProvider("SunRsaSign"); // alg: PS256, PS384, PS512, RS256, RS384, RS512
    static final Provider AES_ENCRYPT_DECRYPT_PROVIDER = Security.getProvider("SunJCE");     // alg: A128GCMKW, A192GCMKW, A256GCMKW, A128KW, A192KW, A256KW
}
