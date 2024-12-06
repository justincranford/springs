package com.github.justincranford.springs.util.jwt;

import com.github.justincranford.springs.util.basic.SecureRandomUtil;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.jwk.Curve;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;

import java.util.List;

import static com.nimbusds.jose.EncryptionMethod.A128CBC_HS256;
import static com.nimbusds.jose.EncryptionMethod.A128GCM;
import static com.nimbusds.jose.EncryptionMethod.A192CBC_HS384;
import static com.nimbusds.jose.EncryptionMethod.A192GCM;
import static com.nimbusds.jose.EncryptionMethod.A256CBC_HS512;
import static com.nimbusds.jose.EncryptionMethod.A256GCM;
import static com.nimbusds.jose.JWEAlgorithm.A128GCMKW;
import static com.nimbusds.jose.JWEAlgorithm.A192GCMKW;
import static com.nimbusds.jose.JWEAlgorithm.A256GCMKW;
import static com.nimbusds.jose.JWEAlgorithm.ECDH_1PU;
import static com.nimbusds.jose.JWEAlgorithm.ECDH_1PU_A128KW;
import static com.nimbusds.jose.JWEAlgorithm.ECDH_1PU_A192KW;
import static com.nimbusds.jose.JWEAlgorithm.ECDH_1PU_A256KW;
import static com.nimbusds.jose.JWEAlgorithm.ECDH_ES;
import static com.nimbusds.jose.JWEAlgorithm.ECDH_ES_A128KW;
import static com.nimbusds.jose.JWEAlgorithm.ECDH_ES_A192KW;
import static com.nimbusds.jose.JWEAlgorithm.ECDH_ES_A256KW;
import static com.nimbusds.jose.JWEAlgorithm.RSA1_5;
import static com.nimbusds.jose.JWEAlgorithm.RSA_OAEP;
import static com.nimbusds.jose.JWEAlgorithm.RSA_OAEP_256;
import static com.nimbusds.jose.JWEAlgorithm.RSA_OAEP_384;
import static com.nimbusds.jose.JWEAlgorithm.RSA_OAEP_512;
import static com.nimbusds.jose.JWSAlgorithm.ES256;
import static com.nimbusds.jose.JWSAlgorithm.ES384;
import static com.nimbusds.jose.JWSAlgorithm.ES512;
import static com.nimbusds.jose.JWSAlgorithm.EdDSA;
import static com.nimbusds.jose.JWSAlgorithm.HS256;
import static com.nimbusds.jose.JWSAlgorithm.HS384;
import static com.nimbusds.jose.JWSAlgorithm.HS512;
import static com.nimbusds.jose.JWSAlgorithm.PS256;
import static com.nimbusds.jose.JWSAlgorithm.PS384;
import static com.nimbusds.jose.JWSAlgorithm.PS512;
import static com.nimbusds.jose.JWSAlgorithm.RS256;
import static com.nimbusds.jose.JWSAlgorithm.RS384;
import static com.nimbusds.jose.JWSAlgorithm.RS512;
import static com.nimbusds.jose.jwk.Curve.Ed25519;
import static com.nimbusds.jose.jwk.Curve.Ed448;
import static com.nimbusds.jose.jwk.Curve.P_256;
import static com.nimbusds.jose.jwk.Curve.P_384;
import static com.nimbusds.jose.jwk.Curve.P_521;

@NoArgsConstructor(access=AccessLevel.PRIVATE)
@SuppressWarnings({"unused", "deprecation"})
public final class AlgorithmUtil {
    /** @see com.nimbusds.jose.jwk.Curve */
    public static final List<Curve> VALID_EC_CURVES = List.of(P_256, P_384, P_521); // omit P_256K

    /** @see com.nimbusds.jose.crypto.impl.EdDSAProvider */
    public static final List<Curve> VALID_ED_CURVES = List.of(Ed25519); // omit Ed448, X25519, X448

    /** @see com.nimbusds.jose.crypto.impl.ECDSAProvider */
    public static final List<JWSAlgorithm> VALID_EC_SIG_VER_ALG = List.of(ES256, ES384, ES512); // omit ES256K

    /** @see com.nimbusds.jose.crypto.impl.ECDHCryptoProvider */
    public static final List<JWEAlgorithm> VALID_EC_ENC_DEC_ALG = List.of(ECDH_ES, ECDH_ES_A128KW, ECDH_ES_A192KW, ECDH_ES_A256KW, ECDH_1PU, ECDH_1PU_A128KW, ECDH_1PU_A192KW, ECDH_1PU_A256KW);

    /** @see com.nimbusds.jose.crypto.impl.EdDSAProvider */
    public static final List<JWSAlgorithm> VALID_ED_SIG_VER_ALG = List.of(EdDSA, JWSAlgorithm.Ed25519); // omit Ed448

    /** @see com.nimbusds.jose.crypto.impl.ECDHCryptoProvider */
    public static final List<JWEAlgorithm> VALID_ED_ENC_DEC_ALG = List.of(ECDH_ES, ECDH_ES_A128KW, ECDH_ES_A192KW, ECDH_ES_A256KW, ECDH_1PU, ECDH_1PU_A128KW, ECDH_1PU_A192KW, ECDH_1PU_A256KW);

    /** @see com.nimbusds.jose.crypto.impl.RSASSAProvider */
    public static final List<JWSAlgorithm> VALID_RSA_SIG_VER_ALG = List.of(RS256, RS384, RS512, PS256, PS384, PS512);

    /** @see com.nimbusds.jose.crypto.impl.RSACryptoProvider */
    public static final List<JWEAlgorithm> VALID_RSA_ENC_DEC_ALG = List.of(RSA1_5, RSA_OAEP, RSA_OAEP_256, RSA_OAEP_384, RSA_OAEP_512);

    /** @see com.nimbusds.jose.crypto.impl.MACProvider */
    public static final List<JWSAlgorithm> VALID_HMAC_SIG_VER_ALG = MACSigner.SUPPORTED_ALGORITHMS.stream().toList();

    public static final List<EncryptionMethod> VALID_AES_ENC_METHODS = List.of(A128CBC_HS256, A192CBC_HS384, A256CBC_HS512, A128GCM, A192GCM, A256GCM);
    public static final List<EncryptionMethod> VALID_RSA_ENC_METHODS = List.of(A128CBC_HS256, A192CBC_HS384, A256CBC_HS512, A128GCM, A192GCM, A256GCM);
    public static final List<EncryptionMethod> VALID_ECDH_ES_ENC_METHODS = List.of(A128CBC_HS256, A192CBC_HS384, A256CBC_HS512, A128GCM, A192GCM, A256GCM);
    public static final List<EncryptionMethod> VALID_ECDH_1PU_ENC_METHODS = List.of(A128CBC_HS256, A192CBC_HS384, A256CBC_HS512); // omit A128GCM, A192GCM, A256GCM

    public static final List<Integer> RSA_LENGTHS_BITS = List.of(2048, 3072, 4096);
    public static final List<Integer> AES_LENGTHS_BITS = List.of(128, 192, 256);
    public static final List<Integer> HMAC_LENGTHS_BITS = List.of(256, 384, 512);

    public static JWSAlgorithm pickJWSAlgorithm(final Curve curve) {
        if (P_256.equals(curve)) {
            return ES256;
        } else if (P_384.equals(curve)) {
            return ES384;
        } else if (P_521.equals(curve)) {
            return ES512;
        } else if (Ed25519.equals(curve)) {
            return SecureRandomUtil.randomListElement(VALID_ED_SIG_VER_ALG);
        } else if (Ed448.equals(curve)) {
            return SecureRandomUtil.randomListElement(VALID_ED_SIG_VER_ALG);
        }
        throw new IllegalArgumentException("Unsupported curve: " + curve); // omit P_256K
    }

    public static JWEAlgorithm pickJWEAlgorithm(final Curve curve) {
        if (P_256.equals(curve)) {
            return SecureRandomUtil.randomListElement(VALID_EC_ENC_DEC_ALG);
        } else if (P_384.equals(curve)) {
            return SecureRandomUtil.randomListElement(VALID_EC_ENC_DEC_ALG);
        } else if (P_521.equals(curve)) {
            return SecureRandomUtil.randomListElement(VALID_EC_ENC_DEC_ALG);
        } else if (Ed25519.equals(curve)) {
            return SecureRandomUtil.randomListElement(VALID_ED_ENC_DEC_ALG);
        } else if (Ed448.equals(curve)) {
            return SecureRandomUtil.randomListElement(VALID_ED_ENC_DEC_ALG);
        }
        throw new IllegalArgumentException("Unsupported curve: " + curve); // omit P_256K
    }

    public static EncryptionMethod pickEncryptionMethod(final JWEAlgorithm alg) {
        if (A128GCMKW.equals(alg) || A192GCMKW.equals(alg) || A256GCMKW.equals(alg)) {
            return SecureRandomUtil.randomListElement(VALID_AES_ENC_METHODS);
        } else if (RSA1_5.equals(alg) || RSA_OAEP.equals(alg) || RSA_OAEP_256.equals(alg) || RSA_OAEP_384.equals(alg) || RSA_OAEP_512.equals(alg)) {
            return SecureRandomUtil.randomListElement(VALID_RSA_ENC_METHODS);
        } else if (ECDH_ES.equals(alg) || ECDH_ES_A128KW.equals(alg) || ECDH_ES_A192KW.equals(alg) || ECDH_ES_A256KW.equals(alg)) {
            return SecureRandomUtil.randomListElement(VALID_ECDH_ES_ENC_METHODS);
        } else if (ECDH_1PU.equals(alg) || ECDH_1PU_A128KW.equals(alg) || ECDH_1PU_A192KW.equals(alg) || ECDH_1PU_A256KW.equals(alg)) {
            return SecureRandomUtil.randomListElement(VALID_ECDH_1PU_ENC_METHODS);
        }
        throw new IllegalArgumentException("Unsupported algorithm: " + alg);
    }

    public static JWSAlgorithm pickHmacAlgorithm(final int hmacLengthBits) {
        if (hmacLengthBits < 384) {
            return HS256;
        } else if (hmacLengthBits < 512) {
            return SecureRandomUtil.randomListElement(List.of(HS256, HS384));
        }
        return SecureRandomUtil.randomListElement(List.of(HS256, HS384, HS512));
    }
}
