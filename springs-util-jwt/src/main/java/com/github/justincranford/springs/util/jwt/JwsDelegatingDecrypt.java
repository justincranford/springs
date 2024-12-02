package com.github.justincranford.springs.util.jwt;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEDecrypter;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jwt.EncryptedJWT;
import lombok.NonNull;

import java.text.ParseException;
import java.util.List;

import static com.github.justincranford.springs.util.jwt.JwkSetUtil.filterJwks;

public class JwsDelegatingDecrypt {
    private final List<JWK> jwks;

    public JwsDelegatingDecrypt(final JWKSet jwkSet) {
        this.jwks = jwkSet.toPublicJWKSet().getKeys();
    }

    public EncryptedJWT verify(@NonNull final EncryptedJWT encryptedJWT) throws JOSEException {
        final List<JWK> filteredJwks = filterJwks(this.jwks, encryptedJWT);
        for (final JWK filteredJwk : filteredJwks) {
            try {
                final JWEDecrypter jweDecrypter = JwtDecryptUtil.jweDecryptor(filteredJwk, encryptedJWT.getHeader().getAlgorithm());
                return JwtDecryptUtil.decrypt(encryptedJWT, jweDecrypter);
            } catch(JOSEException|ParseException e) {
                e.printStackTrace();
            }
        }
        throw new JOSEException("JWT decryption failed with " + filteredJwks.size() + " keys");
    }
}
