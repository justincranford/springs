package com.github.justincranford.springs.util.jwt;

import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.crypto.ECDHEncrypter;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.Curve;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;

import java.util.ArrayList;
import java.util.List;

@NoArgsConstructor(access=AccessLevel.PRIVATE)
public final class AlgorithmUtil {
    public static final ArrayList<JWSAlgorithm> VALID_EC_SIG_VER_ALG = new ArrayList<>(ECDSASigner.SUPPORTED_ALGORITHMS.stream().filter(a -> !a.equals(JWSAlgorithm.ES256K)).toList());
    public static final ArrayList<JWEAlgorithm> VALID_EC_ENC_DEC_ALG = new ArrayList<>(ECDHEncrypter.SUPPORTED_ALGORITHMS.stream().toList());
    public static final ArrayList<JWSAlgorithm> VALID_RSA_SIG_VER_ALG = new ArrayList<>(RSASSASigner.SUPPORTED_ALGORITHMS.stream().toList());
    public static final ArrayList<JWEAlgorithm> VALID_RSA_ENC_DEC_ALG = new ArrayList<>(RSAEncrypter.SUPPORTED_ALGORITHMS.stream().toList());
    public static final ArrayList<JWSAlgorithm> VALID_HMAC_SIG_VER_ALG = new ArrayList<>(MACSigner.SUPPORTED_ALGORITHMS.stream().toList());

    public static final ArrayList<Curve> VALID_EC_CURVES = new ArrayList<>(ECDSASigner.SUPPORTED_CURVES.stream().filter(c -> !c.equals(Curve.SECP256K1)).toList());

    public static final List<Integer> RSA_LENGTHS_BITS = List.of(2048, 3072, 4096);

    public static JWSAlgorithm mapCurveToJWSAlgorithm(Curve curve) {
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
        }
        throw new IllegalArgumentException("Unsupported curve: " + curve);
    }
}
