package com.github.justincranford.springs.util.jwt;

import com.github.justincranford.springs.util.basic.SecureRandomUtil;
import com.github.justincranford.springs.util.basic.TextCodec;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEDecrypter;
import com.nimbusds.jose.JWEEncrypter;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.EncryptedJWT;
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
import static com.github.justincranford.springs.util.jwt.JwtContentUtil.jweHeader;
import static com.github.justincranford.springs.util.jwt.JwtContentUtil.jwsHeader;
import static com.github.justincranford.springs.util.jwt.JwtEncryptUtil.jweEncrypter;
import static com.github.justincranford.springs.util.jwt.JwtSignUtil.VALID_EC_ENC_DEC_ALG;
import static com.github.justincranford.springs.util.jwt.JwtSignUtil.VALID_EC_SIG_VER_ALG;
import static com.github.justincranford.springs.util.jwt.JwtSignUtil.VALID_HMAC_SIG_VER_ALG;
import static com.github.justincranford.springs.util.jwt.JwtSignUtil.VALID_RSA_ENC_DEC_ALG;
import static com.github.justincranford.springs.util.jwt.JwtSignUtil.VALID_RSA_SIG_VER_ALG;
import static com.github.justincranford.springs.util.jwt.JwtSignUtil.jwsSigner;
import static com.github.justincranford.springs.util.jwt.JwtUtilEndToEndTest.ParamsHelper.validDuration;
import static com.github.justincranford.springs.util.jwt.JwtUtilEndToEndTest.ParamsHelper.validJwtClaimsSet;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

@ExtendWith(MockitoExtension.class)
@Slf4j
class JwtUtilEndToEndTest {
    public static class JwsAlg {
        private static final JWSAlgorithm NULL = null;
    }
    public static class JweAlg {
        private static final JWEAlgorithm NULL = null;
    }
    public static class Hmac {
        private static final int BITS_256  = 256; // strength 128-aesBitLen
        private static final int BITS_384  = 384; // strength 192-aesBitLen
        private static final int BITS_512  = 512; // strength 256-aesBitLen
    }
    public static class Aes {
        private static final int BITS_128  = 128; // strength  64-aesBitLen
        private static final int BITS_192  = 192; // strength  96-aesBitLen
        private static final int BITS_256  = 256; // strength 128-aesBitLen
    }
    public static class Rsa {
        private static final int BITS_2048  = 2048; // strength ~112-aesBitLen
        private static final int BITS_3072  = 3072; // strength ~128-aesBitLen
        private static final int BITS_4096  = 4096; // strength ~???-aesBitLen
        private static final int BITS_5120  = 5120; // strength ~???-aesBitLen
        private static final int BITS_6144  = 6144; // strength ~???-aesBitLen
    }

    @ParameterizedTest
    @MethodSource("jwtSignSuccessTestCases")
    void testJwtSignAndVerifySuccess(final SigningTestCase signingTestCase) throws Exception {
        final JWSHeader jwsHeader             = jwsHeader(signingTestCase.jwk, signingTestCase.alg);
        final JWSSigner jwsSigner             = jwsSigner(signingTestCase.jwk);
        final SignedJWT signedJWT             = JwtSignUtil.sign(jwsHeader, signingTestCase.jwtClaimsSet, jwsSigner);
        final String    serializedSignedJWT   = signedJWT.serialize();
        final SignedJWT deserializedSignedJwt = SignedJWT.parse(serializedSignedJWT);
        assertEqualsSignedJwts(signedJWT, deserializedSignedJwt);

        final JWSVerifier verifier         = JwtVerifyUtil.jwsVerifier(signingTestCase.jwk);
        final boolean     isValidSignature = JwtVerifyUtil.verify(deserializedSignedJwt, verifier);
        assertEquals(isValidSignature, signingTestCase.expectValidSignature);
        final boolean     isValidSyntax    = validateSyntax(signedJWT.getJWTClaimsSet());
        assertEquals(isValidSyntax,    signingTestCase.expectValidSyntax);
    }

    @ParameterizedTest
    @MethodSource("validJwtEncryptTestCases")
    void testJwtEncryptAndDecryptSuccess(final EncryptionTestCase encryptionTestCase) throws Exception {
        final JWEHeader    jweHeader                = jweHeader(encryptionTestCase.jwk, encryptionTestCase.alg, encryptionTestCase.enc);
        final JWEEncrypter jweEncrypter             = jweEncrypter(encryptionTestCase.jwk, encryptionTestCase.alg);
        final EncryptedJWT encryptedJWT             = JwtEncryptUtil.encrypt(jweHeader, encryptionTestCase.jwtClaimsSet, jweEncrypter);
        final String       serializedEncryptedJWT   = encryptedJWT.serialize();
        final EncryptedJWT deserializedEncryptedJwt = EncryptedJWT.parse(serializedEncryptedJWT);

        final JWEDecrypter jweDecryptor     = JwtDecryptUtil.jweDecryptor(encryptionTestCase.jwk, encryptionTestCase.alg);
        final EncryptedJWT decryptedJWT     = JwtDecryptUtil.decrypt(deserializedEncryptedJwt, jweDecryptor);
        assertNotNull(decryptedJWT);
        assertEqualsEncryptedJwts(encryptedJWT, decryptedJWT);
        final boolean      isValidSyntax    = validateSyntax(encryptedJWT.getJWTClaimsSet());
        assertEquals(isValidSyntax,    encryptionTestCase.expectValidSyntax);
    }

    static Stream<SigningTestCase> jwtSignSuccessTestCases() throws JOSEException {
        return Stream.of(
//            new SigningTestCase(JWSAlgorithm.RS256, validJwtClaimsSet(), true, true, JwkUtil.rsa (Rsa.BITS_2048, validDuration(), JWSAlgorithm.RS256)),
//            new SigningTestCase(JWSAlgorithm.RS384, validJwtClaimsSet(), true, true, JwkUtil.rsa (Rsa.BITS_2048, validDuration(), JWSAlgorithm.RS384)),
//            new SigningTestCase(JWSAlgorithm.RS512, validJwtClaimsSet(), true, true, JwkUtil.rsa (Rsa.BITS_2048, validDuration(), JWSAlgorithm.RS512)),
//            new SigningTestCase(JWSAlgorithm.RS256, validJwtClaimsSet(), true, true, JwkUtil.rsa (Rsa.BITS_2048, validDuration(), JWSAlgorithm.PS256)),
//            new SigningTestCase(JWSAlgorithm.RS384, validJwtClaimsSet(), true, true, JwkUtil.rsa (Rsa.BITS_2048, validDuration(), JWSAlgorithm.PS384)),
//            new SigningTestCase(JWSAlgorithm.RS512, validJwtClaimsSet(), true, true, JwkUtil.rsa (Rsa.BITS_2048, validDuration(), JWSAlgorithm.PS512)),
//            new SigningTestCase(JWSAlgorithm.ES256, validJwtClaimsSet(), true, true, JwkUtil.ec  (Curve.P_256,   validDuration(), JWSAlgorithm.ES256)),
//            new SigningTestCase(JWSAlgorithm.ES384, validJwtClaimsSet(), true, true, JwkUtil.ec  (Curve.P_384,   validDuration(), JWSAlgorithm.ES384)),
//            new SigningTestCase(JWSAlgorithm.ES512, validJwtClaimsSet(), true, true, JwkUtil.ec  (Curve.P_521,   validDuration(), JWSAlgorithm.ES512)),
//            new SigningTestCase(JWSAlgorithm.HS256, validJwtClaimsSet(), true, true, JwkUtil.hmac(Hmac.BITS_256, validDuration(), JWSAlgorithm.HS256)),
//            new SigningTestCase(JWSAlgorithm.HS384, validJwtClaimsSet(), true, true, JwkUtil.hmac(Hmac.BITS_384, validDuration(), JWSAlgorithm.HS384)),
//            new SigningTestCase(JWSAlgorithm.HS512, validJwtClaimsSet(), true, true, JwkUtil.hmac(Hmac.BITS_512, validDuration(), JWSAlgorithm.HS512)),
//            new SigningTestCase(JWSAlgorithm.RS256, validJwtClaimsSet(), true, true, JwkUtil.rsa (Rsa.BITS_2048, validDuration(), JwsAlg.NULL)),
//            new SigningTestCase(JWSAlgorithm.RS384, validJwtClaimsSet(), true, true, JwkUtil.rsa (Rsa.BITS_2048, validDuration(), JwsAlg.NULL)),
//            new SigningTestCase(JWSAlgorithm.RS512, validJwtClaimsSet(), true, true, JwkUtil.rsa (Rsa.BITS_2048, validDuration(), JwsAlg.NULL)),
//            new SigningTestCase(JWSAlgorithm.RS256, validJwtClaimsSet(), true, true, JwkUtil.rsa (Rsa.BITS_2048, validDuration(), JwsAlg.NULL)),
//            new SigningTestCase(JWSAlgorithm.RS384, validJwtClaimsSet(), true, true, JwkUtil.rsa (Rsa.BITS_2048, validDuration(), JwsAlg.NULL)),
//            new SigningTestCase(JWSAlgorithm.RS512, validJwtClaimsSet(), true, true, JwkUtil.rsa (Rsa.BITS_2048, validDuration(), JwsAlg.NULL)),
//            new SigningTestCase(JWSAlgorithm.ES256, validJwtClaimsSet(), true, true, JwkUtil.ec  (Curve.P_256,   validDuration(), JwsAlg.NULL)),
//            new SigningTestCase(JWSAlgorithm.ES384, validJwtClaimsSet(), true, true, JwkUtil.ec  (Curve.P_384,   validDuration(), JwsAlg.NULL)),
//            new SigningTestCase(JWSAlgorithm.ES512, validJwtClaimsSet(), true, true, JwkUtil.ec  (Curve.P_521,   validDuration(), JwsAlg.NULL)),
//            new SigningTestCase(JWSAlgorithm.HS256, validJwtClaimsSet(), true, true, JwkUtil.hmac(Hmac.BITS_256, validDuration(), JwsAlg.NULL)),
//            new SigningTestCase(JWSAlgorithm.HS384, validJwtClaimsSet(), true, true, JwkUtil.hmac(Hmac.BITS_384, validDuration(), JwsAlg.NULL)),
//            new SigningTestCase(JWSAlgorithm.HS512, validJwtClaimsSet(), true, true, JwkUtil.hmac(Hmac.BITS_512, validDuration(), JwsAlg.NULL))
        );
    }

    @SuppressWarnings({"deprecation"})
    static Stream<EncryptionTestCase> validJwtEncryptTestCases() throws JOSEException {
        return Stream.of(
//            new EncryptionTestCase(JWEAlgorithm.RSA1_5,         EncryptionMethod.A128GCM,       validJwtClaimsSet(), true, true, JwkUtil.rsa(Rsa.BITS_2048, validDuration(), JWEAlgorithm.RSA1_5)),
//            new EncryptionTestCase(JWEAlgorithm.RSA1_5,         EncryptionMethod.A192GCM,       validJwtClaimsSet(), true, true, JwkUtil.rsa(Rsa.BITS_2048, validDuration(), JWEAlgorithm.RSA1_5)),
//            new EncryptionTestCase(JWEAlgorithm.RSA1_5,         EncryptionMethod.A256GCM,       validJwtClaimsSet(), true, true, JwkUtil.rsa(Rsa.BITS_2048, validDuration(), JWEAlgorithm.RSA1_5)),
//            new EncryptionTestCase(JWEAlgorithm.RSA1_5,         EncryptionMethod.A128CBC_HS256, validJwtClaimsSet(), true, true, JwkUtil.rsa(Rsa.BITS_2048, validDuration(), JWEAlgorithm.RSA1_5)),
//            new EncryptionTestCase(JWEAlgorithm.RSA1_5,         EncryptionMethod.A192CBC_HS384, validJwtClaimsSet(), true, true, JwkUtil.rsa(Rsa.BITS_2048, validDuration(), JWEAlgorithm.RSA1_5)),
//            new EncryptionTestCase(JWEAlgorithm.RSA1_5,         EncryptionMethod.A256CBC_HS512, validJwtClaimsSet(), true, true, JwkUtil.rsa(Rsa.BITS_2048, validDuration(), JWEAlgorithm.RSA1_5)),
//            new EncryptionTestCase(JWEAlgorithm.RSA_OAEP,       EncryptionMethod.A128GCM,       validJwtClaimsSet(), true, true, JwkUtil.rsa(Rsa.BITS_2048, validDuration(), JWEAlgorithm.RSA_OAEP)),
//            new EncryptionTestCase(JWEAlgorithm.RSA_OAEP,       EncryptionMethod.A192GCM,       validJwtClaimsSet(), true, true, JwkUtil.rsa(Rsa.BITS_2048, validDuration(), JWEAlgorithm.RSA_OAEP)),
//            new EncryptionTestCase(JWEAlgorithm.RSA_OAEP,       EncryptionMethod.A256GCM,       validJwtClaimsSet(), true, true, JwkUtil.rsa(Rsa.BITS_2048, validDuration(), JWEAlgorithm.RSA_OAEP)),
//            new EncryptionTestCase(JWEAlgorithm.RSA_OAEP,       EncryptionMethod.A128CBC_HS256, validJwtClaimsSet(), true, true, JwkUtil.rsa(Rsa.BITS_2048, validDuration(), JWEAlgorithm.RSA_OAEP)),
//            new EncryptionTestCase(JWEAlgorithm.RSA_OAEP,       EncryptionMethod.A192CBC_HS384, validJwtClaimsSet(), true, true, JwkUtil.rsa(Rsa.BITS_2048, validDuration(), JWEAlgorithm.RSA_OAEP)),
//            new EncryptionTestCase(JWEAlgorithm.RSA_OAEP,       EncryptionMethod.A256CBC_HS512, validJwtClaimsSet(), true, true, JwkUtil.rsa(Rsa.BITS_2048, validDuration(), JWEAlgorithm.RSA_OAEP)),
//            new EncryptionTestCase(JWEAlgorithm.RSA_OAEP_256,   EncryptionMethod.A128GCM,       validJwtClaimsSet(), true, true, JwkUtil.rsa(Rsa.BITS_2048, validDuration(), JWEAlgorithm.RSA_OAEP_256)),
//            new EncryptionTestCase(JWEAlgorithm.RSA_OAEP_384,   EncryptionMethod.A192GCM,       validJwtClaimsSet(), true, true, JwkUtil.rsa(Rsa.BITS_2048, validDuration(), JWEAlgorithm.RSA_OAEP_384)),
//            new EncryptionTestCase(JWEAlgorithm.RSA_OAEP_512,   EncryptionMethod.A256GCM,       validJwtClaimsSet(), true, true, JwkUtil.rsa(Rsa.BITS_2048, validDuration(), JWEAlgorithm.RSA_OAEP_512)),
//            new EncryptionTestCase(JWEAlgorithm.RSA_OAEP_256,   EncryptionMethod.A128CBC_HS256, validJwtClaimsSet(), true, true, JwkUtil.rsa(Rsa.BITS_2048, validDuration(), JWEAlgorithm.RSA_OAEP_256)),
//            new EncryptionTestCase(JWEAlgorithm.RSA_OAEP_384,   EncryptionMethod.A192CBC_HS384, validJwtClaimsSet(), true, true, JwkUtil.rsa(Rsa.BITS_2048, validDuration(), JWEAlgorithm.RSA_OAEP_384)),
//            new EncryptionTestCase(JWEAlgorithm.RSA_OAEP_512,   EncryptionMethod.A256CBC_HS512, validJwtClaimsSet(), true, true, JwkUtil.rsa(Rsa.BITS_2048, validDuration(), JWEAlgorithm.RSA_OAEP_512)),
//            new EncryptionTestCase(JWEAlgorithm.ECDH_ES,        EncryptionMethod.A128GCM,       validJwtClaimsSet(), true, true, JwkUtil.ec (Curve.P_256,   validDuration(), JWEAlgorithm.ECDH_ES)),
//            new EncryptionTestCase(JWEAlgorithm.ECDH_ES,        EncryptionMethod.A192GCM,       validJwtClaimsSet(), true, true, JwkUtil.ec (Curve.P_384,   validDuration(), JWEAlgorithm.ECDH_ES)),
//            new EncryptionTestCase(JWEAlgorithm.ECDH_ES,        EncryptionMethod.A256GCM,       validJwtClaimsSet(), true, true, JwkUtil.ec (Curve.P_521,   validDuration(), JWEAlgorithm.ECDH_ES)),
//            new EncryptionTestCase(JWEAlgorithm.ECDH_ES,        EncryptionMethod.A128CBC_HS256, validJwtClaimsSet(), true, true, JwkUtil.ec (Curve.P_256,   validDuration(), JWEAlgorithm.ECDH_ES)),
//            new EncryptionTestCase(JWEAlgorithm.ECDH_ES,        EncryptionMethod.A192CBC_HS384, validJwtClaimsSet(), true, true, JwkUtil.ec (Curve.P_384,   validDuration(), JWEAlgorithm.ECDH_ES)),
//            new EncryptionTestCase(JWEAlgorithm.ECDH_ES,        EncryptionMethod.A256CBC_HS512, validJwtClaimsSet(), true, true, JwkUtil.ec (Curve.P_521,   validDuration(), JWEAlgorithm.ECDH_ES)),
//            new EncryptionTestCase(JWEAlgorithm.ECDH_ES_A128KW, EncryptionMethod.A128GCM,       validJwtClaimsSet(), true, true, JwkUtil.ec (Curve.P_256,   validDuration(), JWEAlgorithm.ECDH_ES_A128KW)),
//            new EncryptionTestCase(JWEAlgorithm.ECDH_ES_A128KW, EncryptionMethod.A192GCM,       validJwtClaimsSet(), true, true, JwkUtil.ec (Curve.P_384,   validDuration(), JWEAlgorithm.ECDH_ES_A128KW)),
//            new EncryptionTestCase(JWEAlgorithm.ECDH_ES_A128KW, EncryptionMethod.A256GCM,       validJwtClaimsSet(), true, true, JwkUtil.ec (Curve.P_521,   validDuration(), JWEAlgorithm.ECDH_ES_A128KW)),
//            new EncryptionTestCase(JWEAlgorithm.ECDH_ES_A128KW, EncryptionMethod.A128CBC_HS256, validJwtClaimsSet(), true, true, JwkUtil.ec (Curve.P_256,   validDuration(), JWEAlgorithm.ECDH_ES_A128KW)),
//            new EncryptionTestCase(JWEAlgorithm.ECDH_ES_A128KW, EncryptionMethod.A192CBC_HS384, validJwtClaimsSet(), true, true, JwkUtil.ec (Curve.P_384,   validDuration(), JWEAlgorithm.ECDH_ES_A128KW)),
//            new EncryptionTestCase(JWEAlgorithm.ECDH_ES_A128KW, EncryptionMethod.A256CBC_HS512, validJwtClaimsSet(), true, true, JwkUtil.ec (Curve.P_521,   validDuration(), JWEAlgorithm.ECDH_ES_A128KW)),
//            new EncryptionTestCase(JWEAlgorithm.ECDH_ES_A192KW, EncryptionMethod.A128GCM,       validJwtClaimsSet(), true, true, JwkUtil.ec (Curve.P_256,   validDuration(), JWEAlgorithm.ECDH_ES_A192KW)),
//            new EncryptionTestCase(JWEAlgorithm.ECDH_ES_A192KW, EncryptionMethod.A192GCM,       validJwtClaimsSet(), true, true, JwkUtil.ec (Curve.P_384,   validDuration(), JWEAlgorithm.ECDH_ES_A192KW)),
//            new EncryptionTestCase(JWEAlgorithm.ECDH_ES_A192KW, EncryptionMethod.A256GCM,       validJwtClaimsSet(), true, true, JwkUtil.ec (Curve.P_521,   validDuration(), JWEAlgorithm.ECDH_ES_A192KW)),
//            new EncryptionTestCase(JWEAlgorithm.ECDH_ES_A192KW, EncryptionMethod.A128CBC_HS256, validJwtClaimsSet(), true, true, JwkUtil.ec (Curve.P_256,   validDuration(), JWEAlgorithm.ECDH_ES_A192KW)),
//            new EncryptionTestCase(JWEAlgorithm.ECDH_ES_A192KW, EncryptionMethod.A192CBC_HS384, validJwtClaimsSet(), true, true, JwkUtil.ec (Curve.P_384,   validDuration(), JWEAlgorithm.ECDH_ES_A192KW)),
//            new EncryptionTestCase(JWEAlgorithm.ECDH_ES_A192KW, EncryptionMethod.A256CBC_HS512, validJwtClaimsSet(), true, true, JwkUtil.ec (Curve.P_521,   validDuration(), JWEAlgorithm.ECDH_ES_A192KW)),
//            new EncryptionTestCase(JWEAlgorithm.ECDH_ES_A256KW, EncryptionMethod.A128GCM,       validJwtClaimsSet(), true, true, JwkUtil.ec (Curve.P_256,   validDuration(), JWEAlgorithm.ECDH_ES_A256KW)),
//            new EncryptionTestCase(JWEAlgorithm.ECDH_ES_A256KW, EncryptionMethod.A192GCM,       validJwtClaimsSet(), true, true, JwkUtil.ec (Curve.P_384,   validDuration(), JWEAlgorithm.ECDH_ES_A256KW)),
//            new EncryptionTestCase(JWEAlgorithm.ECDH_ES_A256KW, EncryptionMethod.A256GCM,       validJwtClaimsSet(), true, true, JwkUtil.ec (Curve.P_521,   validDuration(), JWEAlgorithm.ECDH_ES_A256KW)),
//            new EncryptionTestCase(JWEAlgorithm.ECDH_ES_A256KW, EncryptionMethod.A128CBC_HS256, validJwtClaimsSet(), true, true, JwkUtil.ec (Curve.P_256,   validDuration(), JWEAlgorithm.ECDH_ES_A256KW)),
//            new EncryptionTestCase(JWEAlgorithm.ECDH_ES_A256KW, EncryptionMethod.A192CBC_HS384, validJwtClaimsSet(), true, true, JwkUtil.ec (Curve.P_384,   validDuration(), JWEAlgorithm.ECDH_ES_A256KW)),
//            new EncryptionTestCase(JWEAlgorithm.ECDH_ES_A256KW, EncryptionMethod.A256CBC_HS512, validJwtClaimsSet(), true, true, JwkUtil.ec (Curve.P_521,   validDuration(), JWEAlgorithm.ECDH_ES_A256KW)),
//            new EncryptionTestCase(JWEAlgorithm.A128GCMKW,      EncryptionMethod.A128GCM,       validJwtClaimsSet(), true, true, JwkUtil.aes(Aes.BITS_128,  validDuration(), JWEAlgorithm.A128GCMKW)),
//            new EncryptionTestCase(JWEAlgorithm.A192GCMKW,      EncryptionMethod.A192GCM,       validJwtClaimsSet(), true, true, JwkUtil.aes(Aes.BITS_192,  validDuration(), JWEAlgorithm.A192GCMKW)),
//            new EncryptionTestCase(JWEAlgorithm.A256GCMKW,      EncryptionMethod.A256GCM,       validJwtClaimsSet(), true, true, JwkUtil.aes(Aes.BITS_256,  validDuration(), JWEAlgorithm.A256GCMKW)),
//            new EncryptionTestCase(JWEAlgorithm.A128GCMKW,      EncryptionMethod.A128CBC_HS256, validJwtClaimsSet(), true, true, JwkUtil.aes(Aes.BITS_128,  validDuration(), JWEAlgorithm.A128GCMKW)),
//            new EncryptionTestCase(JWEAlgorithm.A192GCMKW,      EncryptionMethod.A192CBC_HS384, validJwtClaimsSet(), true, true, JwkUtil.aes(Aes.BITS_192,  validDuration(), JWEAlgorithm.A192GCMKW)),
//            new EncryptionTestCase(JWEAlgorithm.A256GCMKW,      EncryptionMethod.A256CBC_HS512, validJwtClaimsSet(), true, true, JwkUtil.aes(Aes.BITS_256,  validDuration(), JWEAlgorithm.A256GCMKW)),
//            new EncryptionTestCase(JWEAlgorithm.A128KW,         EncryptionMethod.A128GCM,       validJwtClaimsSet(), true, true, JwkUtil.aes(Aes.BITS_128,  validDuration(), JWEAlgorithm.A128KW)),
//            new EncryptionTestCase(JWEAlgorithm.A192KW,         EncryptionMethod.A192GCM,       validJwtClaimsSet(), true, true, JwkUtil.aes(Aes.BITS_192,  validDuration(), JWEAlgorithm.A192KW)),
//            new EncryptionTestCase(JWEAlgorithm.A256KW,         EncryptionMethod.A256GCM,       validJwtClaimsSet(), true, true, JwkUtil.aes(Aes.BITS_256,  validDuration(), JWEAlgorithm.A256KW)),
//            new EncryptionTestCase(JWEAlgorithm.A128KW,         EncryptionMethod.A128CBC_HS256, validJwtClaimsSet(), true, true, JwkUtil.aes(Aes.BITS_128,  validDuration(), JWEAlgorithm.A128KW)),
//            new EncryptionTestCase(JWEAlgorithm.A192KW,         EncryptionMethod.A192CBC_HS384, validJwtClaimsSet(), true, true, JwkUtil.aes(Aes.BITS_192,  validDuration(), JWEAlgorithm.A192KW)),
//            new EncryptionTestCase(JWEAlgorithm.A256KW,         EncryptionMethod.A256CBC_HS512, validJwtClaimsSet(), true, true, JwkUtil.aes(Aes.BITS_256,  validDuration(), JWEAlgorithm.A256KW)),
//            new EncryptionTestCase(JWEAlgorithm.DIR,            EncryptionMethod.A128GCM,       validJwtClaimsSet(), true, true, JwkUtil.aes(Aes.BITS_128,  validDuration(), JWEAlgorithm.DIR)),
//            new EncryptionTestCase(JWEAlgorithm.DIR,            EncryptionMethod.A192GCM,       validJwtClaimsSet(), true, true, JwkUtil.aes(Aes.BITS_192,  validDuration(), JWEAlgorithm.DIR)),
//            new EncryptionTestCase(JWEAlgorithm.DIR,            EncryptionMethod.A256GCM,       validJwtClaimsSet(), true, true, JwkUtil.aes(Aes.BITS_256,  validDuration(), JWEAlgorithm.DIR)),
          new EncryptionTestCase(JWEAlgorithm.DIR,            EncryptionMethod.A128CBC_HS256, validJwtClaimsSet(), true, true, JwkUtil.aes(Aes.BITS_128,  validDuration(), JWEAlgorithm.DIR))
////          new EncryptionTestCase(JWEAlgorithm.DIR,            EncryptionMethod.A192CBC_HS384, validJwtClaimsSet(), true, true, JwkUtil.aes(Aes.BITS_192,  validDuration(), JWEAlgorithm.DIR)),
////          new EncryptionTestCase(JWEAlgorithm.DIR,            EncryptionMethod.A256CBC_HS512, validJwtClaimsSet(), true, true, JwkUtil.aes(Aes.BITS_256,  validDuration(), JWEAlgorithm.DIR)),
//            new EncryptionTestCase(JWEAlgorithm.RSA1_5,         EncryptionMethod.A128GCM,       validJwtClaimsSet(), true, true, JwkUtil.rsa(Rsa.BITS_2048, validDuration(), JweAlg.NULL)),
//            new EncryptionTestCase(JWEAlgorithm.RSA1_5,         EncryptionMethod.A192GCM,       validJwtClaimsSet(), true, true, JwkUtil.rsa(Rsa.BITS_2048, validDuration(), JweAlg.NULL)),
//            new EncryptionTestCase(JWEAlgorithm.RSA1_5,         EncryptionMethod.A256GCM,       validJwtClaimsSet(), true, true, JwkUtil.rsa(Rsa.BITS_2048, validDuration(), JweAlg.NULL)),
//            new EncryptionTestCase(JWEAlgorithm.RSA1_5,         EncryptionMethod.A128CBC_HS256, validJwtClaimsSet(), true, true, JwkUtil.rsa(Rsa.BITS_2048, validDuration(), JweAlg.NULL)),
//            new EncryptionTestCase(JWEAlgorithm.RSA1_5,         EncryptionMethod.A192CBC_HS384, validJwtClaimsSet(), true, true, JwkUtil.rsa(Rsa.BITS_2048, validDuration(), JweAlg.NULL)),
//            new EncryptionTestCase(JWEAlgorithm.RSA1_5,         EncryptionMethod.A256CBC_HS512, validJwtClaimsSet(), true, true, JwkUtil.rsa(Rsa.BITS_2048, validDuration(), JweAlg.NULL)),
//            new EncryptionTestCase(JWEAlgorithm.RSA_OAEP,       EncryptionMethod.A128GCM,       validJwtClaimsSet(), true, true, JwkUtil.rsa(Rsa.BITS_2048, validDuration(), JweAlg.NULL)),
//            new EncryptionTestCase(JWEAlgorithm.RSA_OAEP,       EncryptionMethod.A192GCM,       validJwtClaimsSet(), true, true, JwkUtil.rsa(Rsa.BITS_2048, validDuration(), JweAlg.NULL)),
//            new EncryptionTestCase(JWEAlgorithm.RSA_OAEP,       EncryptionMethod.A256GCM,       validJwtClaimsSet(), true, true, JwkUtil.rsa(Rsa.BITS_2048, validDuration(), JweAlg.NULL)),
//            new EncryptionTestCase(JWEAlgorithm.RSA_OAEP,       EncryptionMethod.A128CBC_HS256, validJwtClaimsSet(), true, true, JwkUtil.rsa(Rsa.BITS_2048, validDuration(), JweAlg.NULL)),
//            new EncryptionTestCase(JWEAlgorithm.RSA_OAEP,       EncryptionMethod.A192CBC_HS384, validJwtClaimsSet(), true, true, JwkUtil.rsa(Rsa.BITS_2048, validDuration(), JweAlg.NULL)),
//            new EncryptionTestCase(JWEAlgorithm.RSA_OAEP,       EncryptionMethod.A256CBC_HS512, validJwtClaimsSet(), true, true, JwkUtil.rsa(Rsa.BITS_2048, validDuration(), JweAlg.NULL)),
//            new EncryptionTestCase(JWEAlgorithm.RSA_OAEP_256,   EncryptionMethod.A128GCM,       validJwtClaimsSet(), true, true, JwkUtil.rsa(Rsa.BITS_2048, validDuration(), JweAlg.NULL)),
//            new EncryptionTestCase(JWEAlgorithm.RSA_OAEP_384,   EncryptionMethod.A192GCM,       validJwtClaimsSet(), true, true, JwkUtil.rsa(Rsa.BITS_2048, validDuration(), JweAlg.NULL)),
//            new EncryptionTestCase(JWEAlgorithm.RSA_OAEP_512,   EncryptionMethod.A256GCM,       validJwtClaimsSet(), true, true, JwkUtil.rsa(Rsa.BITS_2048, validDuration(), JweAlg.NULL)),
//            new EncryptionTestCase(JWEAlgorithm.RSA_OAEP_256,   EncryptionMethod.A128CBC_HS256, validJwtClaimsSet(), true, true, JwkUtil.rsa(Rsa.BITS_2048, validDuration(), JweAlg.NULL)),
//            new EncryptionTestCase(JWEAlgorithm.RSA_OAEP_384,   EncryptionMethod.A192CBC_HS384, validJwtClaimsSet(), true, true, JwkUtil.rsa(Rsa.BITS_2048, validDuration(), JweAlg.NULL)),
//            new EncryptionTestCase(JWEAlgorithm.RSA_OAEP_512,   EncryptionMethod.A256CBC_HS512, validJwtClaimsSet(), true, true, JwkUtil.rsa(Rsa.BITS_2048, validDuration(), JweAlg.NULL)),
//            new EncryptionTestCase(JWEAlgorithm.ECDH_ES,        EncryptionMethod.A128GCM,       validJwtClaimsSet(), true, true, JwkUtil.ec (Curve.P_256,   validDuration(), JweAlg.NULL)),
//            new EncryptionTestCase(JWEAlgorithm.ECDH_ES,        EncryptionMethod.A192GCM,       validJwtClaimsSet(), true, true, JwkUtil.ec (Curve.P_384,   validDuration(), JweAlg.NULL)),
//            new EncryptionTestCase(JWEAlgorithm.ECDH_ES,        EncryptionMethod.A256GCM,       validJwtClaimsSet(), true, true, JwkUtil.ec (Curve.P_521,   validDuration(), JweAlg.NULL)),
//            new EncryptionTestCase(JWEAlgorithm.ECDH_ES,        EncryptionMethod.A128CBC_HS256, validJwtClaimsSet(), true, true, JwkUtil.ec (Curve.P_256,   validDuration(), JweAlg.NULL)),
//            new EncryptionTestCase(JWEAlgorithm.ECDH_ES,        EncryptionMethod.A192CBC_HS384, validJwtClaimsSet(), true, true, JwkUtil.ec (Curve.P_384,   validDuration(), JweAlg.NULL)),
//            new EncryptionTestCase(JWEAlgorithm.ECDH_ES,        EncryptionMethod.A256CBC_HS512, validJwtClaimsSet(), true, true, JwkUtil.ec (Curve.P_521,   validDuration(), JweAlg.NULL)),
//            new EncryptionTestCase(JWEAlgorithm.ECDH_ES_A128KW, EncryptionMethod.A128GCM,       validJwtClaimsSet(), true, true, JwkUtil.ec (Curve.P_256,   validDuration(), JweAlg.NULL)),
//            new EncryptionTestCase(JWEAlgorithm.ECDH_ES_A128KW, EncryptionMethod.A192GCM,       validJwtClaimsSet(), true, true, JwkUtil.ec (Curve.P_384,   validDuration(), JweAlg.NULL)),
//            new EncryptionTestCase(JWEAlgorithm.ECDH_ES_A128KW, EncryptionMethod.A256GCM,       validJwtClaimsSet(), true, true, JwkUtil.ec (Curve.P_521,   validDuration(), JweAlg.NULL)),
//            new EncryptionTestCase(JWEAlgorithm.ECDH_ES_A128KW, EncryptionMethod.A128CBC_HS256, validJwtClaimsSet(), true, true, JwkUtil.ec (Curve.P_256,   validDuration(), JweAlg.NULL)),
//            new EncryptionTestCase(JWEAlgorithm.ECDH_ES_A128KW, EncryptionMethod.A192CBC_HS384, validJwtClaimsSet(), true, true, JwkUtil.ec (Curve.P_384,   validDuration(), JweAlg.NULL)),
//            new EncryptionTestCase(JWEAlgorithm.ECDH_ES_A128KW, EncryptionMethod.A256CBC_HS512, validJwtClaimsSet(), true, true, JwkUtil.ec (Curve.P_521,   validDuration(), JweAlg.NULL)),
//            new EncryptionTestCase(JWEAlgorithm.ECDH_ES_A192KW, EncryptionMethod.A128GCM,       validJwtClaimsSet(), true, true, JwkUtil.ec (Curve.P_256,   validDuration(), JweAlg.NULL)),
//            new EncryptionTestCase(JWEAlgorithm.ECDH_ES_A192KW, EncryptionMethod.A192GCM,       validJwtClaimsSet(), true, true, JwkUtil.ec (Curve.P_384,   validDuration(), JweAlg.NULL)),
//            new EncryptionTestCase(JWEAlgorithm.ECDH_ES_A192KW, EncryptionMethod.A256GCM,       validJwtClaimsSet(), true, true, JwkUtil.ec (Curve.P_521,   validDuration(), JweAlg.NULL)),
//            new EncryptionTestCase(JWEAlgorithm.ECDH_ES_A192KW, EncryptionMethod.A128CBC_HS256, validJwtClaimsSet(), true, true, JwkUtil.ec (Curve.P_256,   validDuration(), JweAlg.NULL)),
//            new EncryptionTestCase(JWEAlgorithm.ECDH_ES_A192KW, EncryptionMethod.A192CBC_HS384, validJwtClaimsSet(), true, true, JwkUtil.ec (Curve.P_384,   validDuration(), JweAlg.NULL)),
//            new EncryptionTestCase(JWEAlgorithm.ECDH_ES_A192KW, EncryptionMethod.A256CBC_HS512, validJwtClaimsSet(), true, true, JwkUtil.ec (Curve.P_521,   validDuration(), JweAlg.NULL)),
//            new EncryptionTestCase(JWEAlgorithm.ECDH_ES_A256KW, EncryptionMethod.A128GCM,       validJwtClaimsSet(), true, true, JwkUtil.ec (Curve.P_256,   validDuration(), JweAlg.NULL)),
//            new EncryptionTestCase(JWEAlgorithm.ECDH_ES_A256KW, EncryptionMethod.A192GCM,       validJwtClaimsSet(), true, true, JwkUtil.ec (Curve.P_384,   validDuration(), JweAlg.NULL)),
//            new EncryptionTestCase(JWEAlgorithm.ECDH_ES_A256KW, EncryptionMethod.A256GCM,       validJwtClaimsSet(), true, true, JwkUtil.ec (Curve.P_521,   validDuration(), JweAlg.NULL)),
//            new EncryptionTestCase(JWEAlgorithm.ECDH_ES_A256KW, EncryptionMethod.A128CBC_HS256, validJwtClaimsSet(), true, true, JwkUtil.ec (Curve.P_256,   validDuration(), JweAlg.NULL)),
//            new EncryptionTestCase(JWEAlgorithm.ECDH_ES_A256KW, EncryptionMethod.A192CBC_HS384, validJwtClaimsSet(), true, true, JwkUtil.ec (Curve.P_384,   validDuration(), JweAlg.NULL)),
//            new EncryptionTestCase(JWEAlgorithm.ECDH_ES_A256KW, EncryptionMethod.A256CBC_HS512, validJwtClaimsSet(), true, true, JwkUtil.ec (Curve.P_521,   validDuration(), JweAlg.NULL)),
//            new EncryptionTestCase(JWEAlgorithm.A128GCMKW,      EncryptionMethod.A128GCM,       validJwtClaimsSet(), true, true, JwkUtil.aes(Aes.BITS_128,  validDuration(), JweAlg.NULL)),
//            new EncryptionTestCase(JWEAlgorithm.A192GCMKW,      EncryptionMethod.A192GCM,       validJwtClaimsSet(), true, true, JwkUtil.aes(Aes.BITS_192,  validDuration(), JweAlg.NULL)),
//            new EncryptionTestCase(JWEAlgorithm.A256GCMKW,      EncryptionMethod.A256GCM,       validJwtClaimsSet(), true, true, JwkUtil.aes(Aes.BITS_256,  validDuration(), JweAlg.NULL)),
//            new EncryptionTestCase(JWEAlgorithm.A128GCMKW,      EncryptionMethod.A128CBC_HS256, validJwtClaimsSet(), true, true, JwkUtil.aes(Aes.BITS_128,  validDuration(), JweAlg.NULL)),
//            new EncryptionTestCase(JWEAlgorithm.A192GCMKW,      EncryptionMethod.A192CBC_HS384, validJwtClaimsSet(), true, true, JwkUtil.aes(Aes.BITS_192,  validDuration(), JweAlg.NULL)),
//            new EncryptionTestCase(JWEAlgorithm.A256GCMKW,      EncryptionMethod.A256CBC_HS512, validJwtClaimsSet(), true, true, JwkUtil.aes(Aes.BITS_256,  validDuration(), JweAlg.NULL)),
//            new EncryptionTestCase(JWEAlgorithm.A128KW,         EncryptionMethod.A128GCM,       validJwtClaimsSet(), true, true, JwkUtil.aes(Aes.BITS_128,  validDuration(), JweAlg.NULL)),
//            new EncryptionTestCase(JWEAlgorithm.A192KW,         EncryptionMethod.A192GCM,       validJwtClaimsSet(), true, true, JwkUtil.aes(Aes.BITS_192,  validDuration(), JweAlg.NULL)),
//            new EncryptionTestCase(JWEAlgorithm.A256KW,         EncryptionMethod.A256GCM,       validJwtClaimsSet(), true, true, JwkUtil.aes(Aes.BITS_256,  validDuration(), JweAlg.NULL)),
//            new EncryptionTestCase(JWEAlgorithm.A128KW,         EncryptionMethod.A128CBC_HS256, validJwtClaimsSet(), true, true, JwkUtil.aes(Aes.BITS_128,  validDuration(), JweAlg.NULL)),
//            new EncryptionTestCase(JWEAlgorithm.A192KW,         EncryptionMethod.A192CBC_HS384, validJwtClaimsSet(), true, true, JwkUtil.aes(Aes.BITS_192,  validDuration(), JweAlg.NULL)),
//            new EncryptionTestCase(JWEAlgorithm.A256KW,         EncryptionMethod.A256CBC_HS512, validJwtClaimsSet(), true, true, JwkUtil.aes(Aes.BITS_256,  validDuration(), JweAlg.NULL)),
//            new EncryptionTestCase(JWEAlgorithm.DIR,            EncryptionMethod.A128GCM,       validJwtClaimsSet(), true, true, JwkUtil.aes(Aes.BITS_128,  validDuration(), JweAlg.NULL)),
//            new EncryptionTestCase(JWEAlgorithm.DIR,            EncryptionMethod.A192GCM,       validJwtClaimsSet(), true, true, JwkUtil.aes(Aes.BITS_192,  validDuration(), JweAlg.NULL)),
//            new EncryptionTestCase(JWEAlgorithm.DIR,            EncryptionMethod.A256GCM,       validJwtClaimsSet(), true, true, JwkUtil.aes(Aes.BITS_256,  validDuration(), JweAlg.NULL))
////          new EncryptionTestCase(JWEAlgorithm.DIR,            EncryptionMethod.A128CBC_HS256, validJwtClaimsSet(), true, true, JwkUtil.aes(Aes.BITS_128,  validDuration(), JweAlg.NULL)),
////          new EncryptionTestCase(JWEAlgorithm.DIR,            EncryptionMethod.A192CBC_HS384, validJwtClaimsSet(), true, true, JwkUtil.aes(Aes.BITS_192,  validDuration(), JweAlg.NULL)),
////          new EncryptionTestCase(JWEAlgorithm.DIR,            EncryptionMethod.A256CBC_HS512, validJwtClaimsSet(), true, true, JwkUtil.aes(Aes.BITS_256,  validDuration(), JweAlg.NULL))
        );
    }

    record SigningTestCase(JWSAlgorithm alg, JWTClaimsSet jwtClaimsSet, boolean expectValidSignature, boolean expectValidSyntax, JWK jwk) {}
    record EncryptionTestCase(JWEAlgorithm alg, EncryptionMethod enc, JWTClaimsSet jwtClaimsSet, boolean expectValidDecrypt, boolean expectValidSyntax, JWK jwk) {}

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

    private static void assertEqualsSignedJwts(final SignedJWT expectedSignedJwt, final SignedJWT actualSignedJwt) throws ParseException {
        final JWSHeader    expectedJwsHeader    = expectedSignedJwt.getHeader();
        final JWTClaimsSet expectedJwtClaimsSet = expectedSignedJwt.getJWTClaimsSet();
        final Base64URL    expectedSignature    = expectedSignedJwt.getSignature();
        log.info("expected SignedJWT:\nHeader: {}\nClaims: {}", expectedJwsHeader, expectedJwtClaimsSet);
        final JWSHeader    actualJwsHeader      = actualSignedJwt.getHeader();
        final JWTClaimsSet actualJwtClaimsSet   = actualSignedJwt.getJWTClaimsSet();
        final Base64URL    actualSignature      = actualSignedJwt.getSignature();
        log.info("actual SignedJWT:\nHeader: {}\nClaims: {}", actualJwsHeader, actualJwtClaimsSet);
        assertEquals(expectedJwsHeader.toJSONObject(),    actualJwsHeader.toJSONObject(),    "JWS headers are not equal");
        assertEquals(expectedJwtClaimsSet.toJSONObject(), actualJwtClaimsSet.toJSONObject(), "JWT claims are not equal");
        assertEquals(expectedSignature,                   actualSignature,                   "JWS signatures are not equal");
    }

    private static void assertEqualsEncryptedJwts(final EncryptedJWT expectedEncryptedJwt, final EncryptedJWT actualEncryptedJwt) throws ParseException {
        final JWEHeader    expectedJweHeader    = expectedEncryptedJwt.getHeader();
        final JWTClaimsSet expectedJwtClaimsSet = expectedEncryptedJwt.getJWTClaimsSet();
        final Base64URL    expectedEncryptedKey = expectedEncryptedJwt.getEncryptedKey();
        final Base64URL    expectedIV           = expectedEncryptedJwt.getIV();
        final Base64URL    expectedAuthTag      = expectedEncryptedJwt.getAuthTag();
        log.info("expected EncryptedJWT:\nHeader: {}\nClaims: {}", expectedJweHeader, expectedJwtClaimsSet);
        final JWEHeader    actualJweHeader      = actualEncryptedJwt.getHeader();
        final JWTClaimsSet actualJwtClaimsSet   = actualEncryptedJwt.getJWTClaimsSet();
        final Base64URL    actualEncryptedKey   = actualEncryptedJwt.getEncryptedKey();
        final Base64URL    actualIV             = actualEncryptedJwt.getIV();
        final Base64URL    actualAuthTag        = actualEncryptedJwt.getAuthTag();
        log.info("actual EncryptedJWT:\nHeader: {}\nClaims: {}", actualJweHeader, actualJwtClaimsSet);
        assertEquals(expectedJweHeader.toJSONObject(),    actualJweHeader.toJSONObject(),    "JWE headers are not equal");
        assertEquals(expectedJwtClaimsSet.toJSONObject(), actualJwtClaimsSet.toJSONObject(), "JWT claims are not equal");
        assertEquals(expectedEncryptedKey,                actualEncryptedKey,                "JWE encrypted keys are not equal");
        assertEquals(expectedIV,                          actualIV,                          "JWE IVs are not equal");
        assertEquals(expectedAuthTag,                     actualAuthTag,                     "JWE auth tags are not equal");
    }
}
