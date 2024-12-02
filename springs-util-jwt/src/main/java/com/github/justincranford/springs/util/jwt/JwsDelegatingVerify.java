package com.github.justincranford.springs.util.jwt;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jwt.SignedJWT;
import lombok.NonNull;

import java.util.List;

import static com.github.justincranford.springs.util.jwt.JwkSetUtil.filterJwks;
import static com.github.justincranford.springs.util.jwt.JwtVerifyUtil.jwsVerifier;

public class JwsDelegatingVerify {
    private final List<JWK> jwks;

    public JwsDelegatingVerify(final JWKSet jwkSet) {
        this.jwks = jwkSet.toPublicJWKSet().getKeys();
    }

    public SignedJWT verify(@NonNull final SignedJWT signedJWT) throws JOSEException {
        final List<JWK> filteredJwks = filterJwks(this.jwks, signedJWT);
        for (final JWK filteredJwk : filteredJwks) {
            try {
                final JWSVerifier jwsVerifier = jwsVerifier(filteredJwk);
                if (JwtVerifyUtil.verify(signedJWT, jwsVerifier)) {
                    return signedJWT;
                }
            } catch(JOSEException e) {
                e.printStackTrace();
            }
        }
        throw new JOSEException("JWT verification failed with " + filteredJwks.size() + " keys");
    }
}
