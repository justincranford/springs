package com.github.justincranford.springs.util.jwt;

import com.github.justincranford.springs.util.basic.DateTimeUtil;
import com.github.justincranford.springs.util.basic.SecureRandomUtil;
import com.github.justincranford.springs.util.basic.TextCodec;
import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyOperation;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.gen.JWKGenerator;
import com.nimbusds.jose.jwk.gen.OctetKeyPairGenerator;
import com.nimbusds.jose.jwk.gen.OctetSequenceKeyGenerator;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;

import java.security.Provider;
import java.time.Duration;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.Date;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import static com.github.justincranford.springs.util.jwt.ProviderUtil.AES_KEY_GENERATOR_PROVIDER;
import static com.github.justincranford.springs.util.jwt.ProviderUtil.EC_KEY_PAIR_GENERATOR_PROVIDER;
import static com.github.justincranford.springs.util.jwt.ProviderUtil.ED_KEY_PAIR_GENERATOR_PROVIDER;
import static com.github.justincranford.springs.util.jwt.ProviderUtil.HMAC_KEY_GENERATOR_PROVIDER;
import static com.github.justincranford.springs.util.jwt.ProviderUtil.RSA_KEY_PAIR_GENERATOR_PROVIDER;

@NoArgsConstructor(access=AccessLevel.PRIVATE)
public final class JwkUtil {
    public static final ArrayList<Curve> VALID_EC_CURVES = new ArrayList<>(ECDSASigner.SUPPORTED_CURVES.stream().filter(c -> !c.equals(Curve.SECP256K1)).toList());

    private static final TextCodec KID_RANDOM_BYTES_CODEC  = TextCodec.B64_URL;
    private static final int       KID_RANDOM_BYTES_LENGTH = 32;

    private static final Set<KeyOperation> KEY_OPS_SIG_VER = new LinkedHashSet<>(List.of(KeyOperation.SIGN,    KeyOperation.VERIFY));
    private static final Set<KeyOperation> KEY_OPS_ENC_DEC = new LinkedHashSet<>(List.of(KeyOperation.ENCRYPT, KeyOperation.DECRYPT));

    public static OctetKeyPair ed(final Algorithm alg, final Curve curve, final Duration duration) throws JOSEException {
        return generate(new OctetKeyPairGenerator(curve), alg, ED_KEY_PAIR_GENERATOR_PROVIDER, duration, KeyUse.SIGNATURE, KEY_OPS_SIG_VER);
    }
    public static ECKey ec(final Algorithm alg, final Curve curve, final Duration duration) throws JOSEException {
        return generate(new ECKeyGenerator(curve), alg, EC_KEY_PAIR_GENERATOR_PROVIDER, duration, KeyUse.SIGNATURE, KEY_OPS_SIG_VER);
    }
    public static RSAKey rsa(final Algorithm alg, final int keyLengthBits, final Duration duration) throws JOSEException {
        return generate(new RSAKeyGenerator(keyLengthBits), alg, RSA_KEY_PAIR_GENERATOR_PROVIDER, duration, KeyUse.SIGNATURE, KEY_OPS_SIG_VER);
    }
    public static OctetSequenceKey hmac(final JWSAlgorithm alg, final int keyLengthBits, final Duration duration) throws JOSEException {
        return generate(new OctetSequenceKeyGenerator(keyLengthBits), alg, HMAC_KEY_GENERATOR_PROVIDER, duration, KeyUse.SIGNATURE, KEY_OPS_SIG_VER);
    }
    public static OctetSequenceKey aes(final JWEAlgorithm alg, final int keyLengthBits, final Duration duration) throws JOSEException {
        return generate(new OctetSequenceKeyGenerator(keyLengthBits), alg, AES_KEY_GENERATOR_PROVIDER, duration, KeyUse.ENCRYPTION, KEY_OPS_ENC_DEC);
    }

    private static <JWK_GENERATOR extends JWKGenerator<JWK_TYPE>, JWK_TYPE extends JWK> JWK_TYPE generate(
        final JWK_GENERATOR     jwkGenerator,
        final Algorithm         alg,
        final Provider          keyGeneratorProvider,
        final Duration          duration,
        final KeyUse            keyUse,
        final Set<KeyOperation> keyOps
    ) throws JOSEException {
        final String         kid = SecureRandomUtil.randomString(KID_RANDOM_BYTES_CODEC, KID_RANDOM_BYTES_LENGTH);
        final OffsetDateTime now = DateTimeUtil.nowUtcTruncatedToNanoseconds();
        final Date           iat = Date.from(now.toInstant());
        final Date           nbf = Date.from(now.toInstant());
        final Date           exp = Date.from(now.plus(duration).toInstant());
        return jwkGenerator
            .secureRandom(SecureRandomUtil.SECURE_RANDOM)
            .provider(keyGeneratorProvider)
            .algorithm(alg)
            .keyID(kid)
            .keyUse(keyUse)
            .keyOperations(keyOps)
            .issueTime(iat)
            .notBeforeTime(nbf)
            .expirationTime(exp)
            .generate();
    }

    public static JWSAlgorithm ecSignVerifyAlg(final Curve curve) {
        if (Curve.P_256.equals(curve)) {
            return JWSAlgorithm.ES256;
        } else if (Curve.P_384.equals(curve)) {
            return JWSAlgorithm.ES384;
        } else if (Curve.P_521.equals(curve)) {
            return JWSAlgorithm.ES512;
        } else if (Curve.Ed25519.equals(curve)) {
            return JWSAlgorithm.EdDSA;
        } else if (Curve.Ed448.equals(curve)) {
            return JWSAlgorithm.EdDSA;
        } else {
            throw new IllegalArgumentException("Unsupported curve: " + curve.getName());
        }
    }

    public static JWEAlgorithm toEcAlg(final Curve curve) {
        if (Curve.P_256.equals(curve)) {
            return JWEAlgorithm.ECDH_ES_A128KW;  // ECDH_ES_A128KW, ECDH_ES_A192KW, ECDH_ES_A256KW => Suitable for P-256 is ECDH_ES_A128KW
        } else if (Curve.P_384.equals(curve)) {
            return JWEAlgorithm.ECDH_ES_A192KW;  // ECDH_ES_A128KW, ECDH_ES_A192KW, ECDH_ES_A256KW => Suitable for P-384 is ECDH_ES_A128KW
        } else if (Curve.P_521.equals(curve)) {
            return JWEAlgorithm.ECDH_ES_A256KW;  // ECDH_ES_A128KW, ECDH_ES_A192KW, ECDH_ES_A256KW => Suitable for P-521 is ECDH_ES_A128KW
        } else if (Curve.Ed25519.equals(curve)) {
            return JWEAlgorithm.ECDH_ES_A256KW;  // ECDH_ES_A128KW, ECDH_ES_A256KW                 => Common for Ed25519 is ECDH_ES_A128KW
        } else if (Curve.Ed448.equals(curve)) {
            return JWEAlgorithm.ECDH_ES_A256KW;  // ECDH_ES_A128KW, ECDH_ES_A256KW                 => Common for Ed448 is ECDH_ES_A128KW
        } else {
            throw new IllegalArgumentException("Unsupported curve: " + curve.getName());
        }
    }

    public static Curve toEcCurve(final JWEAlgorithm jweAlgorithm) {
        if (JWEAlgorithm.ECDH_ES.equals(jweAlgorithm)) {
            return Curve.P_256;
        } else if (JWEAlgorithm.ECDH_ES_A128KW.equals(jweAlgorithm)) {
            return Curve.P_256;
        } else if (JWEAlgorithm.ECDH_ES_A192KW.equals(jweAlgorithm)) {
            return Curve.P_384;
        } else if (JWEAlgorithm.ECDH_ES_A256KW.equals(jweAlgorithm)) {
            return Curve.P_521;
        } else {
            throw new IllegalArgumentException("Unsupported JWEAlgorithm: " + jweAlgorithm.getName());
        }
    }
}
