package com.github.justincranford.springs.util.jwt;

import com.github.justincranford.springs.util.basic.SecureRandomUtil;
import com.github.justincranford.springs.util.basic.TextCodec;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.junit.jupiter.MockitoExtension;

import java.text.ParseException;
import java.time.Duration;
import java.util.List;
import java.util.Set;
import java.util.stream.Stream;

import static com.github.justincranford.springs.util.jwt.JwkUtil.VALID_EC_CURVES;
import static com.github.justincranford.springs.util.jwt.JwtClaimSetUtil.validateSyntax;
import static com.github.justincranford.springs.util.jwt.JwtContentUtil.jwsHeader;
import static com.github.justincranford.springs.util.jwt.JwtSignUtil.VALID_EC_ENC_DEC_ALG;
import static com.github.justincranford.springs.util.jwt.JwtSignUtil.VALID_EC_SIG_VER_ALG;
import static com.github.justincranford.springs.util.jwt.JwtSignUtil.VALID_HMAC_SIG_VER_ALG;
import static com.github.justincranford.springs.util.jwt.JwtSignUtil.VALID_RSA_ENC_DEC_ALG;
import static com.github.justincranford.springs.util.jwt.JwtSignUtil.VALID_RSA_SIG_VER_ALG;
import static com.github.justincranford.springs.util.jwt.JwtSignUtil.jwsSigner;
import static com.github.justincranford.springs.util.jwt.JwtUtilEndToEndTest.ParamsHelper.invalidJwtClaimsSetExp;
import static com.github.justincranford.springs.util.jwt.JwtUtilEndToEndTest.ParamsHelper.validDuration;
import static com.github.justincranford.springs.util.jwt.JwtUtilEndToEndTest.ParamsHelper.validEcCurve;
import static com.github.justincranford.springs.util.jwt.JwtUtilEndToEndTest.ParamsHelper.validEcEncryptDecryptAlg;
import static com.github.justincranford.springs.util.jwt.JwtUtilEndToEndTest.ParamsHelper.validEcSignVerifyAlg;
import static com.github.justincranford.springs.util.jwt.JwtUtilEndToEndTest.ParamsHelper.validHmacLengthBits;
import static com.github.justincranford.springs.util.jwt.JwtUtilEndToEndTest.ParamsHelper.validHmacSignVerifyAlg;
import static com.github.justincranford.springs.util.jwt.JwtUtilEndToEndTest.ParamsHelper.validJwtClaimsSet;
import static com.github.justincranford.springs.util.jwt.JwtUtilEndToEndTest.ParamsHelper.validRsaEncryptDecryptAlg;
import static com.github.justincranford.springs.util.jwt.JwtUtilEndToEndTest.ParamsHelper.validRsaLengthBits;
import static com.github.justincranford.springs.util.jwt.JwtUtilEndToEndTest.ParamsHelper.validRsaSignVerifyAlg;
import static org.junit.jupiter.api.Assertions.assertEquals;

@ExtendWith(MockitoExtension.class)
@Slf4j
class JwtUtilEndToEndTest {
    @ParameterizedTest
    @MethodSource("jwtSignSuccessTestCases")
    void testJwtSignAndVerifySuccess(SigningTestCase signingTestCase) throws Exception {
        final JWSHeader jwsHeader             = jwsHeader(signingTestCase.jwk);
        final JWSSigner jwsSigner             = jwsSigner(signingTestCase.jwk);
        final SignedJWT signedJWT             = JwtSignUtil.sign(jwsHeader, signingTestCase.jwtClaimsSet, jwsSigner);
        final String    serializedSignedJWT   = signedJWT.serialize();
        final SignedJWT deserializedSignedJwt = SignedJWT.parse(serializedSignedJWT);
        assertEqualsSignedJwts(signedJWT, deserializedSignedJwt);

        final JWSVerifier verifier         = JwtVerifyUtil.jwsVerifier(signingTestCase.jwk);
        final boolean     isValidSignature = JwtVerifyUtil.verify(deserializedSignedJwt, verifier);
        final boolean     isValidSyntax    = validateSyntax(signedJWT.getJWTClaimsSet());
        assertEquals(isValidSignature, signingTestCase.expectValidSignature);
        assertEquals(isValidSyntax,    signingTestCase.expectValidSyntax);
    }

    private static void assertEqualsSignedJwts(final SignedJWT expectedSignedJWT, final SignedJWT actualSignedJwt) throws ParseException {
        final JWSHeader    expectedJwsHeader    = expectedSignedJWT.getHeader();
        final JWTClaimsSet expectedJwtClaimsSet = expectedSignedJWT.getJWTClaimsSet();
        final Base64URL    expectedSignature    = expectedSignedJWT.getSignature();
        log.info("expected SignedJWT:\nHeader: {}\nClaims: {}", expectedJwsHeader, expectedJwtClaimsSet);
        final JWSHeader    actualJwsHeader      = actualSignedJwt.getHeader();
        final JWTClaimsSet actualJwtClaimsSet   = actualSignedJwt.getJWTClaimsSet();
        final Base64URL    actualSignature      = actualSignedJwt.getSignature();
        log.info("actual SignedJWT:\nHeader: {}\nClaims: {}", actualJwsHeader, actualJwtClaimsSet);
        assertEquals(expectedJwsHeader.toJSONObject(),    actualJwsHeader.toJSONObject(),    "JWT headers are not equal");
        assertEquals(expectedJwtClaimsSet.toJSONObject(), actualJwtClaimsSet.toJSONObject(), "JWT claims are not equal");
        assertEquals(expectedSignature,                   actualSignature,                   "JWT signatures are not equal");
    }

    static Stream<SigningTestCase> jwtSignSuccessTestCases() throws JOSEException {
        return Stream.of(
            new SigningTestCase(JwkUtil.rsa(validRsaSignVerifyAlg(), validRsaLengthBits(), validDuration()), validJwtClaimsSet(), true, true),
            new SigningTestCase(JwkUtil.ec(validEcSignVerifyAlg(), validEcCurve(), validDuration()), validJwtClaimsSet(), true, true),
            new SigningTestCase(JwkUtil.hmac(validHmacSignVerifyAlg(), validHmacLengthBits(), validDuration()), validJwtClaimsSet(), true, true),
            new SigningTestCase(JwkUtil.rsa(validRsaSignVerifyAlg(), validRsaLengthBits(), validDuration()), invalidJwtClaimsSetExp(), true, false),
            new SigningTestCase(JwkUtil.ec(validEcSignVerifyAlg(), validEcCurve(), validDuration()), invalidJwtClaimsSetExp(), true, false)
        );
    }

    static Stream<EncryptionTestCase> validJwtEncryptTestCases() throws JOSEException {
        return Stream.of(
            new EncryptionTestCase(JwkUtil.rsa(validRsaEncryptDecryptAlg(), validRsaLengthBits(), validDuration()), validJwtClaimsSet(), JWEAlgorithm.RSA_OAEP_256, true, true),
            new EncryptionTestCase(JwkUtil.ec(validEcEncryptDecryptAlg(), validEcCurve(), validDuration()), validJwtClaimsSet(), JWEAlgorithm.ECDH_ES_A128KW, true, true),
            new EncryptionTestCase(JwkUtil.hmac(validHmacSignVerifyAlg(), validHmacLengthBits(), validDuration()), validJwtClaimsSet(), JWEAlgorithm.A128GCMKW, true, true),
            new EncryptionTestCase(JwkUtil.rsa(validRsaEncryptDecryptAlg(), validRsaLengthBits(), validDuration()), invalidJwtClaimsSetExp(), JWEAlgorithm.RSA_OAEP_256, true, false),
            new EncryptionTestCase(JwkUtil.ec(validEcEncryptDecryptAlg(), validEcCurve(), validDuration()), invalidJwtClaimsSetExp(), JWEAlgorithm.ECDH_ES_A128KW, true, false)
        );
    }

    record SigningTestCase(JWK jwk, JWTClaimsSet jwtClaimsSet, boolean expectValidSignature, boolean expectValidSyntax) {}
    record EncryptionTestCase(JWK jwk, JWTClaimsSet claimsSet, JWEAlgorithm alg, boolean expectValidIntegrity, boolean expectValidSyntax) {}

    @NoArgsConstructor(access=AccessLevel.PRIVATE)
    static final class ParamsHelper {
        static JWTClaimsSet validJwtClaimsSet() {
            return JwtContentUtil.jwtClaimsSetBuilder(validIssuer(), validAudiences(), validSubject(), validDuration(), validScopes()).build();
        }
        static JWTClaimsSet invalidJwtClaimsSetExp() {
            return JwtContentUtil.jwtClaimsSetBuilder(validIssuer(), validAudiences(), validSubject(), invalidDuration(), validScopes()).build();
        }

        static Curve validEcCurve() {
            return SecureRandomUtil.randomListElement(VALID_EC_CURVES);
        }
        static JWSAlgorithm validEcSignVerifyAlg() {
            return SecureRandomUtil.randomListElement(VALID_EC_SIG_VER_ALG);
        }
        static JWEAlgorithm validEcEncryptDecryptAlg() {
            return SecureRandomUtil.randomListElement(VALID_EC_ENC_DEC_ALG);
        }
        static int validRsaLengthBits() {
            return 2048;
        }
        static JWSAlgorithm validRsaSignVerifyAlg() {
            return SecureRandomUtil.randomListElement(VALID_RSA_SIG_VER_ALG);
        }
        static JWEAlgorithm validRsaEncryptDecryptAlg() {
            return SecureRandomUtil.randomListElement(VALID_RSA_ENC_DEC_ALG);
        }
        static int validHmacLengthBits() {
            return 512;
        }
        static JWSAlgorithm validHmacSignVerifyAlg() {
            return SecureRandomUtil.randomListElement(VALID_HMAC_SIG_VER_ALG);
        }

        static String validIssuer() {
            return "iss-" + SecureRandomUtil.randomString(TextCodec.B64_STD, 8);
        }
        static List<String> validAudiences() {
            return List.of("aud-" + SecureRandomUtil.randomString(TextCodec.B64_STD, 8));
        }
        static String validSubject() {
            return "sub-" + SecureRandomUtil.randomString(TextCodec.B64_STD, 8);
        }
        static Set<String> validScopes() {
            return Set.of("scope-" + SecureRandomUtil.randomString(TextCodec.B64_STD, 8));
        }
        static Duration validDuration() {
            return Duration.ofHours(1);
        }
        static Duration invalidDuration() {
            return Duration.ofHours(-1);
        }
    }
}
