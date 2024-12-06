package com.github.justincranford.springs.util.jwt;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.KeyLengthException;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.Ed25519Signer;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;

import java.security.Provider;
import java.time.Duration;
import java.util.List;
import java.util.Set;

import static com.github.justincranford.springs.util.jwt.JwtContentUtil.jwsHeader;
import static com.github.justincranford.springs.util.jwt.JwtContentUtil.jwtClaimsSet;
import static com.github.justincranford.springs.util.jwt.ProviderUtil.EC_SIGN_VERIFY_PROVIDER;
import static com.github.justincranford.springs.util.jwt.ProviderUtil.ED_SIGN_VERIFY_PROVIDER;
import static com.github.justincranford.springs.util.jwt.ProviderUtil.HMAC_SIGN_VERIFY_PROVIDER;
import static com.github.justincranford.springs.util.jwt.ProviderUtil.RSA_SIGN_VERIFY_PROVIDER;

@NoArgsConstructor(access=AccessLevel.PRIVATE)
public final class JwtSignUtil {
    public static JWSSigner jwsSigner(final JWK jwk) throws JOSEException {
        if (jwk instanceof OctetKeyPair) {
            return edSigner(jwk.toOctetKeyPair(), ED_SIGN_VERIFY_PROVIDER);
        } else if (jwk instanceof ECKey) {
            return ecSigner(jwk.toECKey(), EC_SIGN_VERIFY_PROVIDER);
        } else if (jwk instanceof RSAKey) {
            return rsaSigner(jwk.toRSAKey(), RSA_SIGN_VERIFY_PROVIDER);
        } else if (jwk instanceof OctetSequenceKey) {
            return hmacSigner(jwk.toOctetSequenceKey(), HMAC_SIGN_VERIFY_PROVIDER);
        }
        throw new JOSEException("Unsupported key type for signing");
    }

    public static Ed25519Signer edSigner(final OctetKeyPair edKey, final Provider provider) throws JOSEException {
        return new Ed25519Signer(edKey.toOctetKeyPair());
    }
    public static ECDSASigner ecSigner(final ECKey ecKey, final Provider provider) throws JOSEException {
        return new ECDSASigner(ecKey.toECPrivateKey());
    }
    public static RSASSASigner rsaSigner(final RSAKey rsaKey, final Provider provider) throws JOSEException {
        return new RSASSASigner(rsaKey.toRSAPrivateKey());
    }
    public static MACSigner hmacSigner(final OctetSequenceKey octetSequenceKey, final Provider provider) throws KeyLengthException {
        return new MACSigner(octetSequenceKey.toByteArray());
    }

    public static SignedJWT sign(final JWK jwk, final JWSAlgorithm alg, final String iss, final List<String> aud, final String sub, final Duration duration, final Set<String> scopes) throws Exception {
        final JWSHeader    jwsHeader     = jwsHeader(jwk, alg);
        final JWTClaimsSet jwtClaimsSet  = jwtClaimsSet(iss, aud, sub, duration, scopes);
        final JWSSigner    jwsSigner     = jwsSigner(jwk);
        return sign(jwsHeader, jwtClaimsSet, jwsSigner);
    }

    public static SignedJWT sign(final JWSHeader jwsHeader, final JWTClaimsSet jwtClaimsSet, final JWSSigner jwsSigner) throws JOSEException {
        final SignedJWT toBeSignedJWT = new SignedJWT(jwsHeader, jwtClaimsSet);
        return sign(toBeSignedJWT, jwsSigner);
    }

    private static SignedJWT sign(final SignedJWT toBeSignedJWT, final JWSSigner jwsSigner) throws JOSEException {
        toBeSignedJWT.sign(jwsSigner);
        return toBeSignedJWT;
    }
}
