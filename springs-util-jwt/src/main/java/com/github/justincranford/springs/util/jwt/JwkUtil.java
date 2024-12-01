package com.github.justincranford.springs.util.jwt;

import com.github.justincranford.springs.util.basic.DateTimeUtil;
import com.github.justincranford.springs.util.basic.SecureRandomUtil;
import com.github.justincranford.springs.util.basic.TextCodec;
import com.github.justincranford.springs.util.basic.ThreadUtil;
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
import lombok.NonNull;

import java.security.Provider;
import java.time.Duration;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.Date;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;

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

    public static OctetKeyPair ed(final Curve curve, final Duration duration, final Algorithm alg) throws JOSEException {
        return generate(new OctetKeyPairGenerator(curve), alg, ED_KEY_PAIR_GENERATOR_PROVIDER, duration, KeyUse.SIGNATURE, KEY_OPS_SIG_VER);
    }
    public static ECKey ec(final Curve curve, final Duration duration, final Algorithm alg) throws JOSEException {
        return generate(new ECKeyGenerator(curve), alg, EC_KEY_PAIR_GENERATOR_PROVIDER, duration, KeyUse.SIGNATURE, KEY_OPS_SIG_VER);
    }
    public static RSAKey rsa(final int keyLengthBits, final Duration duration, final Algorithm alg) throws JOSEException {
        return generate(new RSAKeyGenerator(keyLengthBits), alg, RSA_KEY_PAIR_GENERATOR_PROVIDER, duration, KeyUse.SIGNATURE, KEY_OPS_SIG_VER);
    }
    public static OctetSequenceKey hmac(final int keyLengthBits, final Duration duration, final Algorithm alg) throws JOSEException {
        return generate(new OctetSequenceKeyGenerator(keyLengthBits), alg, HMAC_KEY_GENERATOR_PROVIDER, duration, KeyUse.SIGNATURE, KEY_OPS_SIG_VER);
    }
    public static OctetSequenceKey aes(final int keyLengthBits, final Duration duration, final Algorithm alg) throws JOSEException {
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
        final String         kid = KID_RANDOM_BYTES_CODEC.encodeToString(SecureRandomUtil.timeStampBytesAndRandomBytes(8, KID_RANDOM_BYTES_LENGTH));
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


    public static List<JWK> generateList(@NonNull Duration duration, int numEdSign, int numEcSign, int numRsaSign, int numHmacSign, int numEcEncrypt, int numRsaEncrypt, int numAesEncrypt) {
        final List<Future<JWK>> futureJwkList = new ArrayList<>(numEdSign + numEcSign + numRsaSign + numHmacSign + numEcEncrypt + numRsaEncrypt + numAesEncrypt);

        for (int i = 0; i < numEdSign; i++) {
            futureJwkList.add(ThreadUtil.supplyAsync(() -> JwkUtil.ed(Curve.Ed25519, duration, JWSAlgorithm.Ed25519)));
        }
        for (int i = 0; i < numEcSign; i++) {
            futureJwkList.add(ThreadUtil.supplyAsync(() -> JwkUtil.ec(Curve.P_256, duration, JWSAlgorithm.ES256)));
        }
        for (int i = 0; i < numRsaSign; i++) {
            futureJwkList.add(ThreadUtil.supplyAsync(() -> JwkUtil.rsa(2048, duration, JWSAlgorithm.PS256)));
        }
        for (int i = 0; i < numHmacSign; i++) {
            futureJwkList.add(ThreadUtil.supplyAsync(() -> JwkUtil.hmac(256, duration, JWSAlgorithm.HS256)));
        }

        for (int i = 0; i < numEcEncrypt; i++) {
            futureJwkList.add(ThreadUtil.supplyAsync(() -> JwkUtil.ec(Curve.P_256, duration, JWEAlgorithm.ECDH_ES_A256KW)));
        }
        for (int i = 0; i < numRsaEncrypt; i++) {
            futureJwkList.add(ThreadUtil.supplyAsync(() -> JwkUtil.rsa(2048, duration, JWEAlgorithm.RSA_OAEP_256)));
        }
        for (int i = 0; i < numAesEncrypt; i++) {
            futureJwkList.add(ThreadUtil.supplyAsync(() -> JwkUtil.aes(256, duration, JWEAlgorithm.A256GCMKW)));
        }

        return futureJwkList.stream().map(futureJwk -> {
            try {
                return futureJwk.get();
            } catch (InterruptedException | ExecutionException e) {
                throw new RuntimeException(e);
            }
        }).toList();
    }
}
