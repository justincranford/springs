package com.github.justincranford.springs.util.jwt;

import com.github.justincranford.springs.util.basic.DateTimeUtil;
import com.github.justincranford.springs.util.basic.SecureRandomUtil;
import com.github.justincranford.springs.util.basic.TextCodec;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jwt.JWTClaimsSet;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;

import java.time.Duration;
import java.time.OffsetDateTime;
import java.util.Date;
import java.util.List;
import java.util.Set;

@NoArgsConstructor(access=AccessLevel.PRIVATE)
public final class JwtContentUtil {
    public static final TextCodec JTI_RANDOM_BYTES_CODEC   = TextCodec.B64_URL;
    public static final int       JTI_RANDOM_BYTES_LENGTH = 32;
    public static final TextCodec NONCE_RANDOM_BYTES_CODEC   = TextCodec.B64_URL;
    public static final int       NONCE_RANDOM_BYTES_LENGTH = 32;

    public static JWSHeader jwsHeader(final JWK jwk, final JWSAlgorithm alg) {
//        final JWSAlgorithm   alg = Objects.requireNonNull((JWSAlgorithm) jwk.getAlgorithm()); // JWK.alg optional, JWT.alg mandatory
        final JOSEObjectType typ = JOSEObjectType.JWT; // mandatory
        final String         kid = jwk.getKeyID(); // JWK.kid and JWT.kid both optional
        return new JWSHeader.Builder(alg).type(typ).keyID(kid).build();
    }

    public static JWEHeader jweHeader(final JWK jwk, final JWEAlgorithm alg, final EncryptionMethod enc) {
//        final JWEAlgorithm     alg = Objects.requireNonNull((JWEAlgorithm) jwk.getAlgorithm()); // JWK.alg optional, JWT.alg mandatory
        final JOSEObjectType   typ = JOSEObjectType.JWT; // mandatory
        final String           kid = jwk.getKeyID(); // JWK.kid and JWT.kid both optional
        return new JWEHeader.Builder(alg, enc).type(typ).keyID(kid).build();
    }

    public static JWTClaimsSet jwtClaimsSet(final String iss, final List<String> aud, final String sub, final Duration duration, final Set<String> scopes) {
        return jwtClaimsSetBuilder(iss, aud, sub, duration, scopes).build();
    }

    public static JWTClaimsSet.Builder jwtClaimsSetBuilder(final String iss, final List<String> aud, final String sub, final Duration duration, final Set<String> scopes) {
        final String         jti   = SecureRandomUtil.randomString(JTI_RANDOM_BYTES_CODEC, JTI_RANDOM_BYTES_LENGTH);
        final String         nonce = SecureRandomUtil.randomString(NONCE_RANDOM_BYTES_CODEC, NONCE_RANDOM_BYTES_LENGTH);
        final OffsetDateTime now   = DateTimeUtil.nowUtcTruncatedToNanoseconds();
        final Date           iat   = Date.from(now.toInstant());
        final Date           nbf   = Date.from(now.toInstant());
        final Date           exp   = Date.from(now.plus(duration).toInstant());
        final String         scope = String.join(" ", scopes);
        return new JWTClaimsSet.Builder()
            .jwtID(jti)
            .issuer(iss)
            .audience(aud)
            .subject(sub)
            .issueTime(iat)
            .notBeforeTime(nbf)
            .expirationTime(exp)
            .claim("nonce", nonce)
            .claim("scope", scope);
    }
}
