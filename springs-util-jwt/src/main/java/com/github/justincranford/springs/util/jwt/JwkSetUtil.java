package com.github.justincranford.springs.util.jwt;

import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.SignedJWT;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import lombok.NonNull;

import javax.annotation.Nullable;
import java.time.Duration;
import java.util.List;
import java.util.Objects;

import static com.github.justincranford.springs.util.jwt.JwkUtil.generateList;

@NoArgsConstructor(access=AccessLevel.PRIVATE)
public final class JwkSetUtil {
    public static JWKSet generateSet(@NonNull Duration duration, int numEdSign, int numEcSign, int numRsaSign, int numHmacSign, int numEcEncrypt, int numRsaEncrypt, int numAesEncrypt) {
        return new JWKSet(generateList(duration, numEdSign, numEcSign, numRsaSign, numHmacSign, numEcEncrypt, numRsaEncrypt, numAesEncrypt));
    }

    public static List<JWK> filterJwks(final @NonNull JWKSet jwkSet, final @NonNull JWT jwt) {
        if (jwt instanceof SignedJWT signedJWT) {
            return filterJwks(jwkSet, signedJWT.getHeader());
        } else if (jwt instanceof EncryptedJWT encryptedJWT) {
            return filterJwks(jwkSet, encryptedJWT.getHeader());
        }
        return List.of();
    }

    public static List<JWK> filterJwks(final @NonNull JWKSet jwkSet, final @NonNull SignedJWT signedJWT) {
        return filterJwks(jwkSet, signedJWT.getHeader());
    }

    public static List<JWK> filterJwks(final @NonNull JWKSet jwkSet, final @NonNull EncryptedJWT encryptedJWT) {
        return filterJwks(jwkSet, encryptedJWT.getHeader());
    }

    private static List<JWK> filterJwks(final @NonNull JWKSet jwkSet, final @NonNull JWSHeader jwsHeader) {
        return jwkSet.getKeys().stream()
             .filter(Objects::nonNull)
             .filter(jwk -> isJwkKidMatch(jwsHeader.getKeyID(), jwk.getKeyID()))
             .filter(jwk -> isJwkAlgMatch(jwk, jwsHeader.getAlgorithm()))
             .toList();
    }

    private static List<JWK> filterJwks(final @NonNull JWKSet jwkSet, final @NonNull JWEHeader jweHeader) {
        return jwkSet.getKeys().stream()
             .filter(Objects::nonNull)
             .filter(jwk -> isJwkKidMatch(jwk.getKeyID(), jweHeader.getKeyID()))
             .filter(jwk -> isJwkAlgMatch(jwk, jweHeader.getAlgorithm()))
             .toList();
    }

    private static boolean isJwkKidMatch(final @Nullable String jwtKid, final @Nullable String jwkKid) {
        return (jwtKid == null) || (jwkKid == null) || jwtKid.equals(jwkKid);
    }

    private static boolean isJwkAlgMatch(final @NonNull JWK jwk, final @Nullable JWSAlgorithm jwtAlg) {
        if ((JWSAlgorithm.NONE.equals(jwtAlg))) {
            return false; // JWT alg is explicitly non-signature
        } else if (!((jwk instanceof RSAKey) || (jwk instanceof ECKey) || (jwk instanceof OctetKeyPair) || (jwk instanceof OctetSequenceKey))) {
            return false; // JWK type is implicitly non-signature (or null)
        }
        final Algorithm jwkAlg = jwk.getAlgorithm();
        if ((jwkAlg != null) && (!(jwkAlg instanceof JWSAlgorithm) || (JWSAlgorithm.NONE.equals(jwkAlg)))) {
            return false; // JWK alg is specified, and explicitly non-signature
        }
        if ((jwtAlg == null) || (jwkAlg == null)) {
            return true; // JWT alg or JWK alg not specified, so JWK is considered a potential match
        }
        return jwtAlg.equals(jwkAlg); // JWT alg and JWK alg both specified, exact match required
    }

    private static boolean isJwkAlgMatch(final @NonNull JWK jwk, final @Nullable JWEAlgorithm jwtAlg) {
        if ((JWEAlgorithm.NONE.equals(jwtAlg))) {
            return false; // JWT alg is explicitly non-signature
        } else if (!((jwk instanceof RSAKey) || (jwk instanceof ECKey) || (jwk instanceof OctetSequenceKey))) {
            return false; // JWK type is implicitly non-signature (or null)
        }
        final Algorithm jwkAlg = jwk.getAlgorithm();
        if ((jwkAlg != null) && (!(jwkAlg instanceof JWEAlgorithm) || (JWEAlgorithm.NONE.equals(jwkAlg)))) {
            return false; // JWK alg is specified, and explicitly non-signature
        }
        if ((jwtAlg == null) || (jwkAlg == null)) {
            return true; // JWT alg or JWK alg not specified, so JWK is considered a potential match
        }
        return jwtAlg.equals(jwkAlg); // JWT alg and JWK alg both specified, exact match required
    }
}
