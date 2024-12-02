package com.github.justincranford.springs.util.jwt;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.Ed25519Verifier;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.SignedJWT;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import lombok.NonNull;

import java.security.Provider;

import static com.github.justincranford.springs.util.jwt.ProviderUtil.EC_SIGN_VERIFY_PROVIDER;
import static com.github.justincranford.springs.util.jwt.ProviderUtil.ED_SIGN_VERIFY_PROVIDER;
import static com.github.justincranford.springs.util.jwt.ProviderUtil.HMAC_SIGN_VERIFY_PROVIDER;
import static com.github.justincranford.springs.util.jwt.ProviderUtil.RSA_SIGN_VERIFY_PROVIDER;

@NoArgsConstructor(access=AccessLevel.PRIVATE)
public final class JwtVerifyUtil {
    public static JWSVerifier jwsVerifier(@NonNull final JWK jwk) throws JOSEException {
        if (jwk instanceof OctetKeyPair) {
            return edVerifier(jwk.toOctetKeyPair(), ED_SIGN_VERIFY_PROVIDER);
        } else if (jwk instanceof ECKey) {
            return ecVerifier(jwk.toECKey(), EC_SIGN_VERIFY_PROVIDER);
        } else if (jwk instanceof RSAKey) {
            return rsaVerifier(jwk.toRSAKey(), RSA_SIGN_VERIFY_PROVIDER);
        } else if (jwk instanceof OctetSequenceKey) {
            return hmacVerifier(jwk.toOctetSequenceKey(), HMAC_SIGN_VERIFY_PROVIDER);
        }
        throw new JOSEException("Unsupported key type for verifying");
    }

    public static Ed25519Verifier edVerifier(@NonNull final OctetKeyPair edKey, @NonNull final Provider provider) throws JOSEException {
        return new Ed25519Verifier(edKey.toOctetKeyPair().toPublicJWK());
    }
    public static ECDSAVerifier ecVerifier(@NonNull final ECKey ecKey, @NonNull final Provider provider) throws JOSEException {
        return new ECDSAVerifier(ecKey.toECPublicKey());
    }
    public static RSASSAVerifier rsaVerifier(@NonNull final RSAKey rsaKey, @NonNull final Provider provider) throws JOSEException {
        return new RSASSAVerifier(rsaKey.toRSAPublicKey());
    }
    public static MACVerifier hmacVerifier(@NonNull final OctetSequenceKey octetSequenceKey, @NonNull final Provider provider) throws JOSEException {
        return new MACVerifier(octetSequenceKey.toByteArray());
    }

    public static boolean verify(@NonNull final SignedJWT signedJWT, @NonNull final JWK jwk, @NonNull final Provider provider) throws JOSEException {
        final JWSVerifier jwsVerifier = jwsVerifier(jwk);
        return signedJWT.verify(jwsVerifier);
    }

    public static boolean verify(@NonNull final SignedJWT signedJWT, @NonNull final JWSVerifier jwsVerifier) throws JOSEException {
        return signedJWT.verify(jwsVerifier);
    }
}
