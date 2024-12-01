package com.github.justincranford.springs.util.jwt;

import com.github.justincranford.springs.util.basic.Timer;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.junit.jupiter.MockitoExtension;

import java.text.ParseException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

import static com.github.justincranford.springs.util.jwt.JwkSetUtil.generateSet;
import static com.github.justincranford.springs.util.jwt.JwkUtil.generateList;
import static com.github.justincranford.springs.util.jwt.JwtContentUtil.jweHeader;
import static com.github.justincranford.springs.util.jwt.JwtContentUtil.jwsHeader;
import static com.github.justincranford.springs.util.jwt.JwtDecryptUtil.decrypt;
import static com.github.justincranford.springs.util.jwt.JwtDecryptUtil.jweDecryptor;
import static com.github.justincranford.springs.util.jwt.JwtEncryptUtil.encrypt;
import static com.github.justincranford.springs.util.jwt.JwtEncryptUtil.jweEncrypter;
import static com.github.justincranford.springs.util.jwt.JwtSignUtil.jwsSigner;
import static com.github.justincranford.springs.util.jwt.JwtSignUtil.sign;
import static com.github.justincranford.springs.util.jwt.JwtVerifyUtil.jwsVerifier;
import static com.github.justincranford.springs.util.jwt.JwtVerifyUtil.verify;
import static com.github.justincranford.springs.util.jwt.ParamsHelper.validJwtClaimsSet;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

@ExtendWith(MockitoExtension.class)
public final class JwkSetUtilTest {
    record TestCase(JWT jwt, JWK jwk, JWKSet jwkSet, boolean expectFindJwk, boolean expectValid) {}

    static Stream<TestCase> generateTestCases() throws JOSEException {
        try (final Timer ignore = Timer.go("generateTestCases")) {
            final int numEdSign     = 2;
            final int numEcSign     = 2;
            final int numRsaSign    = 2;
            final int numHmacSign   = 2;
            final int numEcEncrypt  = 2;
            final int numRsaEncrypt = 2;
            final int numAesEncrypt = 2;
            final List<JWK> jwkList;
            try (final Timer ignore2 = Timer.go("generateJwks")) {
                jwkList = generateList(Duration.ofMinutes(1), numEdSign, numEcSign, numRsaSign, numHmacSign, numEcEncrypt, numRsaEncrypt, numAesEncrypt);
            }
            final JWKSet jwkSetAllJwks = new JWKSet(jwkList);
            final JWKSet jwkSetNoJwks  = new JWKSet();

            try (final Timer ignore2 = Timer.go("generateJwts")) {
                final List<TestCase> testCases = new ArrayList<>();
                for (final JWK jwk : jwkList) {
                    final JWKSet jwkSetOneJwk  = new JWKSet(jwk);
                    if (jwk.getAlgorithm() instanceof JWSAlgorithm jwsAlg) {
                        final SignedJWT signedJwt1 = sign(jwsHeader(jwk, jwsAlg), validJwtClaimsSet(), jwsSigner(jwk));
                        final SignedJWT signedJwt2 = sign(jwsHeader(jwk, jwsAlg), validJwtClaimsSet(), jwsSigner(jwk));
                        final SignedJWT signedJwt3 = sign(jwsHeader(jwk, jwsAlg), validJwtClaimsSet(), jwsSigner(jwk));
                        testCases.add(new TestCase(signedJwt1, jwk, jwkSetOneJwk,  true,  true));
                        testCases.add(new TestCase(signedJwt2, jwk, jwkSetAllJwks, true,  true));
                        testCases.add(new TestCase(signedJwt3, jwk, jwkSetNoJwks,  false, false));
                    } else if (jwk.getAlgorithm() instanceof JWEAlgorithm jweAlg) {
                        final EncryptedJWT encryptedJwt1 = encrypt(jweHeader(jwk, jweAlg, EncryptionMethod.A128GCM), validJwtClaimsSet(), jweEncrypter(jwk, jweAlg));
                        final EncryptedJWT encryptedJwt2 = encrypt(jweHeader(jwk, jweAlg, EncryptionMethod.A128GCM), validJwtClaimsSet(), jweEncrypter(jwk, jweAlg));
                        final EncryptedJWT encryptedJwt3 = encrypt(jweHeader(jwk, jweAlg, EncryptionMethod.A128GCM), validJwtClaimsSet(), jweEncrypter(jwk, jweAlg));
                        testCases.add(new TestCase(encryptedJwt1, jwk, jwkSetOneJwk,  true,  true));
                        testCases.add(new TestCase(encryptedJwt2, jwk, jwkSetAllJwks, true,  true));
                        testCases.add(new TestCase(encryptedJwt3, jwk, jwkSetNoJwks,  false, false));
                    } else {
                        throw new JOSEException("Unexpected JWK alg " + jwk.getAlgorithm());
                    }
                }
                return testCases.stream();
            }
        }
    }

    @Disabled
    @Test
    void testGenerate() {
        int numEdSign = 1;
        int numEcSign = 1;
        int numRsaSign = 1;
        int numHmacSign = 1;
        int numEcEncrypt = 1;
        int numRsaEncrypt = 1;
        int numAesEncrypt = 1;
        JWKSet generatedJwkSet = generateSet(Duration.ofHours(1), numEdSign, numEcSign, numRsaSign, numHmacSign, numEcEncrypt, numRsaEncrypt, numAesEncrypt);
        assertNotNull(generatedJwkSet);
        assertEquals(numEdSign + numEcSign + numRsaSign + numHmacSign + numEcEncrypt + numRsaEncrypt + numAesEncrypt, generatedJwkSet.getKeys().size());
    }

    @ParameterizedTest
    @MethodSource("generateTestCases")
    void testFilterJwks(TestCase testCase) throws JOSEException, ParseException {
        JWT jwt = testCase.jwt();
        JWK jwk = testCase.jwk();
        JWKSet jwkSet = testCase.jwkSet();
        boolean expectFoundJwk = testCase.expectFindJwk();
        boolean expectValid = testCase.expectValid();

        final List<JWK> jwkList = JwkSetUtil.filterJwks(jwkSet, jwt);
        if (expectFoundJwk) {
            assertEquals(1, jwkList.size());
            assertTrue(jwkList.contains(jwk));
        } else {
            assertEquals(0, jwkList.size());
        }
        if (expectValid) {
            if (jwt instanceof SignedJWT signedJWT) {
                verify(signedJWT, jwsVerifier(jwk));
            } else if (jwt instanceof EncryptedJWT encryptedJWT) {
                decrypt(encryptedJWT, jweDecryptor(jwk, encryptedJWT.getHeader().getAlgorithm()));
            }
        }
    }
}
