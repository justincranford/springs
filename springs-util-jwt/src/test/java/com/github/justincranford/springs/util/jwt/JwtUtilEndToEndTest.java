package com.github.justincranford.springs.util.jwt;

import com.github.justincranford.springs.util.basic.ThreadUtil;
import com.github.justincranford.springs.util.basic.Timer;
import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.EncryptionMethod;
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
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.junit.jupiter.MockitoExtension;

import java.security.Security;
import java.text.ParseException;
import java.util.concurrent.Future;
import java.util.stream.Stream;

import static com.github.justincranford.springs.util.jwt.JwkUtil.aes;
import static com.github.justincranford.springs.util.jwt.JwkUtil.ec;
import static com.github.justincranford.springs.util.jwt.JwkUtil.ed;
import static com.github.justincranford.springs.util.jwt.JwkUtil.hmac;
import static com.github.justincranford.springs.util.jwt.JwkUtil.rsa;
import static com.github.justincranford.springs.util.jwt.JwtClaimSetUtil.validate;
import static com.github.justincranford.springs.util.jwt.JwtContentUtil.jweHeader;
import static com.github.justincranford.springs.util.jwt.JwtContentUtil.jwsHeader;
import static com.github.justincranford.springs.util.jwt.JwtDecryptUtil.decrypt;
import static com.github.justincranford.springs.util.jwt.JwtDecryptUtil.jweDecryptor;
import static com.github.justincranford.springs.util.jwt.JwtEncryptUtil.encrypt;
import static com.github.justincranford.springs.util.jwt.JwtEncryptUtil.jweEncrypter;
import static com.github.justincranford.springs.util.jwt.JwtSignUtil.jwsSigner;
import static com.github.justincranford.springs.util.jwt.JwtSignUtil.sign;
import static com.github.justincranford.springs.util.jwt.JwtUtilEndToEndTest.Bits.B_128;
import static com.github.justincranford.springs.util.jwt.JwtUtilEndToEndTest.Bits.B_192;
import static com.github.justincranford.springs.util.jwt.JwtUtilEndToEndTest.Bits.B_2048;
import static com.github.justincranford.springs.util.jwt.JwtUtilEndToEndTest.Bits.B_256;
import static com.github.justincranford.springs.util.jwt.JwtUtilEndToEndTest.Bits.B_384;
import static com.github.justincranford.springs.util.jwt.JwtUtilEndToEndTest.Bits.B_512;
import static com.github.justincranford.springs.util.jwt.JwtUtilEndToEndTest.JAlg.NULL;
import static com.github.justincranford.springs.util.jwt.JwtVerifyUtil.jwsVerifier;
import static com.github.justincranford.springs.util.jwt.JwtVerifyUtil.verify;
import static com.github.justincranford.springs.util.jwt.ParamsHelper.validDuration;
import static com.github.justincranford.springs.util.jwt.ParamsHelper.validJwtClaimsSet;
import static com.nimbusds.jose.EncryptionMethod.A128CBC_HS256;
import static com.nimbusds.jose.EncryptionMethod.A128GCM;
import static com.nimbusds.jose.EncryptionMethod.A192CBC_HS384;
import static com.nimbusds.jose.EncryptionMethod.A192GCM;
import static com.nimbusds.jose.EncryptionMethod.A256CBC_HS512;
import static com.nimbusds.jose.EncryptionMethod.A256GCM;
import static com.nimbusds.jose.EncryptionMethod.XC20P;
import static com.nimbusds.jose.JWEAlgorithm.A128GCMKW;
import static com.nimbusds.jose.JWEAlgorithm.A128KW;
import static com.nimbusds.jose.JWEAlgorithm.A192GCMKW;
import static com.nimbusds.jose.JWEAlgorithm.A192KW;
import static com.nimbusds.jose.JWEAlgorithm.A256GCMKW;
import static com.nimbusds.jose.JWEAlgorithm.A256KW;
import static com.nimbusds.jose.JWEAlgorithm.DIR;
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
import static com.nimbusds.jose.JWSAlgorithm.Ed25519;
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
import static com.nimbusds.jose.jwk.Curve.P_256;
import static com.nimbusds.jose.jwk.Curve.P_384;
import static com.nimbusds.jose.jwk.Curve.P_521;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

@ExtendWith(MockitoExtension.class)
@Slf4j
@SuppressWarnings({"unused", "deprecation"})
class JwtUtilEndToEndTest {
    @BeforeAll
    public static void beforeAll() {
        Security.addProvider(new BouncyCastleProvider());
    }

    @AfterAll
    public static void afterAll() {
        Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME);
    }

    @ParameterizedTest
    @MethodSource("jwtSignSuccessTestCases")
    void testJwtSignAndVerifySuccess(final SigningTestCase signingTestCase) throws Exception {
        final JWSHeader jwsHeader             = jwsHeader(signingTestCase.jwk.get(), signingTestCase.alg);
        final JWSSigner jwsSigner             = jwsSigner(signingTestCase.jwk.get());
        final SignedJWT signedJwt             = sign(jwsHeader, signingTestCase.jwtClaimsSet, jwsSigner);
        final String    serializedSignedJwt   = signedJwt.serialize();
        final SignedJWT deserializedSignedJwt = SignedJWT.parse(serializedSignedJwt);

        assertEqualJwts(signedJwt, deserializedSignedJwt); // JWTClaimsSet is cleartext after deserialize, no need to wait for verify

        final JWSVerifier verifier         = jwsVerifier(signingTestCase.jwk.get());
        final boolean     isValidSignature = verify(deserializedSignedJwt, verifier); // verify signature only
        assertEquals(isValidSignature, signingTestCase.expectValidSignature);

        final boolean isValidContents = validate(signedJwt.getJWTClaimsSet()); // verify JWTClaimsSet contents
        assertEquals(isValidContents, signingTestCase.expectValidSyntax);
    }

    @ParameterizedTest
    @MethodSource("validJwtEncryptTestCases")
    void testJwtEncryptAndDecryptSuccess(final EncryptionTestCase encryptionTestCase) throws Exception {
        final JWEHeader    jweHeader                = jweHeader(encryptionTestCase.jwk.get(), encryptionTestCase.alg, encryptionTestCase.enc);
        final JWEEncrypter jweEncrypter             = jweEncrypter(encryptionTestCase.jwk.get(), encryptionTestCase.alg);
        final EncryptedJWT encryptedJwt             = encrypt(jweHeader, encryptionTestCase.jwtClaimsSet, jweEncrypter);
        final String       serializedEncryptedJwt   = encryptedJwt.serialize();
        final EncryptedJWT deserializedEncryptedJwt = EncryptedJWT.parse(serializedEncryptedJwt);

        final JWEDecrypter jweDecryptor = jweDecryptor(encryptionTestCase.jwk.get(), encryptionTestCase.alg);
        final EncryptedJWT decryptedJwt = decrypt(deserializedEncryptedJwt, jweDecryptor); // decrypt. as well as verify MAC
        assertNotNull(decryptedJwt);

        assertEqualJwts(encryptedJwt, decryptedJwt); // JWTClaimsSet is cleartext only after deserialize and decrypt, need to wait for decrypt

        final boolean isValidContents = validate(encryptedJwt.getJWTClaimsSet()); // verify JWTClaimsSet contents
        assertEquals(isValidContents, encryptionTestCase.expectValidSyntax);
    }

    record SigningTestCase(JWSAlgorithm alg, JWTClaimsSet jwtClaimsSet, boolean expectValidSignature, boolean expectValidSyntax, Future<JWK> jwk) {}
    static Stream<SigningTestCase> jwtSignSuccessTestCases() {
        try (final Timer ignores = Timer.go("jwtSignSuccessTestCases")) {
            return Stream.of(
                new SigningTestCase(EdDSA,   validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> ed(Curve.Ed25519, validDuration(), EdDSA))),
                new SigningTestCase(Ed25519, validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> ed(Curve.Ed25519, validDuration(), Ed25519))),
//              new SigningTestCase(EdDSA,   validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> ed(Curve.Ed448,   validDuration(), EdDSA))),
//              new SigningTestCase(Ed448,   validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> ed(Curve.Ed448,   validDuration(), Ed448))),
                new SigningTestCase(ES256,   validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> ec(P_256,   validDuration(), ES256))),
                new SigningTestCase(ES384,   validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> ec(P_384,   validDuration(), ES384))),
                new SigningTestCase(ES512,   validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> ec(P_521,   validDuration(), ES512))),
                new SigningTestCase(RS256,   validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> rsa(B_2048, validDuration(), RS256))),
                new SigningTestCase(RS384,   validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> rsa(B_2048, validDuration(), RS384))),
                new SigningTestCase(RS512,   validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> rsa(B_2048, validDuration(), RS512))),
                new SigningTestCase(PS256,   validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> rsa(B_2048, validDuration(), PS256))),
                new SigningTestCase(PS384,   validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> rsa(B_2048, validDuration(), PS384))),
                new SigningTestCase(PS512,   validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> rsa(B_2048, validDuration(), PS512))),
                new SigningTestCase(HS256,   validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> hmac(B_256, validDuration(), HS256))),
                new SigningTestCase(HS384,   validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> hmac(B_384, validDuration(), HS384))),
                new SigningTestCase(HS512,   validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> hmac(B_512, validDuration(), HS512))),

                new SigningTestCase(EdDSA,   validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> ed(Curve.Ed25519, validDuration(), NULL))),
                new SigningTestCase(Ed25519, validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> ed(Curve.Ed25519, validDuration(), NULL))),
//              new SigningTestCase(EdDSA,   validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> ed(Ed448,   validDuration(), NULL))),
//              new SigningTestCase(Ed448,   validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> ed(Ed448,   validDuration(), NULL))),
                new SigningTestCase(ES256,   validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> ec(P_256,   validDuration(), NULL))),
                new SigningTestCase(ES384,   validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> ec(P_384,   validDuration(), NULL))),
                new SigningTestCase(ES512,   validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> ec(P_521,   validDuration(), NULL))),
                new SigningTestCase(RS256,   validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> rsa(B_2048, validDuration(), NULL))),
                new SigningTestCase(RS384,   validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> rsa(B_2048, validDuration(), NULL))),
                new SigningTestCase(RS512,   validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> rsa(B_2048, validDuration(), NULL))),
                new SigningTestCase(PS256,   validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> rsa(B_2048, validDuration(), NULL))),
                new SigningTestCase(PS384,   validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> rsa(B_2048, validDuration(), NULL))),
                new SigningTestCase(PS512,   validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> rsa(B_2048, validDuration(), NULL))),
                new SigningTestCase(HS256,   validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> hmac(B_256, validDuration(), NULL))),
                new SigningTestCase(HS384,   validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> hmac(B_384, validDuration(), NULL))),
                new SigningTestCase(HS512,   validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> hmac(B_512, validDuration(), NULL)))
            );
        }
    }

    record EncryptionTestCase(JWEAlgorithm alg, EncryptionMethod enc, JWTClaimsSet jwtClaimsSet, boolean expectValidDecrypt, boolean expectValidSyntax, Future<JWK> jwk) {}
    static Stream<EncryptionTestCase> validJwtEncryptTestCases() {
        try (final Timer ignores = Timer.go("validJwtEncryptTestCases")) {
            return Stream.of(
                new EncryptionTestCase(RSA1_5,          A128GCM,       validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> rsa(B_2048, validDuration(), RSA1_5))),
                new EncryptionTestCase(RSA1_5,          A192GCM,       validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> rsa(B_2048, validDuration(), RSA1_5))),
                new EncryptionTestCase(RSA1_5,          A256GCM,       validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> rsa(B_2048, validDuration(), RSA1_5))),
                new EncryptionTestCase(RSA1_5,          A128CBC_HS256, validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> rsa(B_2048, validDuration(), RSA1_5))),
                new EncryptionTestCase(RSA1_5,          A192CBC_HS384, validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> rsa(B_2048, validDuration(), RSA1_5))),
                new EncryptionTestCase(RSA1_5,          A256CBC_HS512, validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> rsa(B_2048, validDuration(), RSA1_5))),
                new EncryptionTestCase(RSA1_5,          XC20P,         validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> rsa(B_2048, validDuration(), RSA1_5))),
                new EncryptionTestCase(RSA_OAEP,        A128GCM,       validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> rsa(B_2048, validDuration(), RSA_OAEP))),
                new EncryptionTestCase(RSA_OAEP,        A192GCM,       validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> rsa(B_2048, validDuration(), RSA_OAEP))),
                new EncryptionTestCase(RSA_OAEP,        A256GCM,       validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> rsa(B_2048, validDuration(), RSA_OAEP))),
                new EncryptionTestCase(RSA_OAEP,        A128CBC_HS256, validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> rsa(B_2048, validDuration(), RSA_OAEP))),
                new EncryptionTestCase(RSA_OAEP,        A192CBC_HS384, validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> rsa(B_2048, validDuration(), RSA_OAEP))),
                new EncryptionTestCase(RSA_OAEP,        A256CBC_HS512, validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> rsa(B_2048, validDuration(), RSA_OAEP))),
                new EncryptionTestCase(RSA_OAEP,        XC20P,         validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> rsa(B_2048, validDuration(), RSA_OAEP))),
                new EncryptionTestCase(RSA_OAEP_256,    A128GCM,       validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> rsa(B_2048, validDuration(), RSA_OAEP_256))),
                new EncryptionTestCase(RSA_OAEP_384,    A192GCM,       validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> rsa(B_2048, validDuration(), RSA_OAEP_384))),
                new EncryptionTestCase(RSA_OAEP_512,    A256GCM,       validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> rsa(B_2048, validDuration(), RSA_OAEP_512))),
                new EncryptionTestCase(RSA_OAEP_256,    A128CBC_HS256, validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> rsa(B_2048, validDuration(), RSA_OAEP_256))),
                new EncryptionTestCase(RSA_OAEP_384,    A192CBC_HS384, validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> rsa(B_2048, validDuration(), RSA_OAEP_384))),
                new EncryptionTestCase(RSA_OAEP_512,    A256CBC_HS512, validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> rsa(B_2048, validDuration(), RSA_OAEP_512))),
                new EncryptionTestCase(RSA_OAEP_512,    XC20P,         validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> rsa(B_2048, validDuration(), RSA_OAEP_512))),
                new EncryptionTestCase(ECDH_ES,         A128GCM,       validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> ec(P_256,  validDuration(), ECDH_ES))),
                new EncryptionTestCase(ECDH_ES,         A192GCM,       validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> ec(P_384,  validDuration(), ECDH_ES))),
                new EncryptionTestCase(ECDH_ES,         A256GCM,       validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> ec(P_521,  validDuration(), ECDH_ES))),
                new EncryptionTestCase(ECDH_ES,         A128CBC_HS256, validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> ec(P_256,  validDuration(), ECDH_ES))),
                new EncryptionTestCase(ECDH_ES,         A192CBC_HS384, validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> ec(P_384,  validDuration(), ECDH_ES))),
                new EncryptionTestCase(ECDH_ES,         A256CBC_HS512, validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> ec(P_521,  validDuration(), ECDH_ES))),
                new EncryptionTestCase(ECDH_ES,         XC20P,         validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> ec(P_521,  validDuration(), ECDH_ES))),
                new EncryptionTestCase(ECDH_ES_A128KW,  A128GCM,       validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> ec(P_256,  validDuration(), ECDH_ES_A128KW))),
                new EncryptionTestCase(ECDH_ES_A128KW,  A192GCM,       validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> ec(P_384,  validDuration(), ECDH_ES_A128KW))),
                new EncryptionTestCase(ECDH_ES_A128KW,  A256GCM,       validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> ec(P_521,  validDuration(), ECDH_ES_A128KW))),
                new EncryptionTestCase(ECDH_ES_A128KW,  A128CBC_HS256, validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> ec(P_256,  validDuration(), ECDH_ES_A128KW))),
                new EncryptionTestCase(ECDH_ES_A128KW,  A192CBC_HS384, validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> ec(P_384,  validDuration(), ECDH_ES_A128KW))),
                new EncryptionTestCase(ECDH_ES_A128KW,  A256CBC_HS512, validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> ec(P_521,  validDuration(), ECDH_ES_A128KW))),
                new EncryptionTestCase(ECDH_ES_A128KW,  XC20P,         validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> ec(P_521,  validDuration(), ECDH_ES_A128KW))),
                new EncryptionTestCase(ECDH_ES_A192KW,  A128GCM,       validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> ec(P_256,  validDuration(), ECDH_ES_A192KW))),
                new EncryptionTestCase(ECDH_ES_A192KW,  A192GCM,       validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> ec(P_384,  validDuration(), ECDH_ES_A192KW))),
                new EncryptionTestCase(ECDH_ES_A192KW,  A256GCM,       validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> ec(P_521,  validDuration(), ECDH_ES_A192KW))),
                new EncryptionTestCase(ECDH_ES_A192KW,  A128CBC_HS256, validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> ec(P_256,  validDuration(), ECDH_ES_A192KW))),
                new EncryptionTestCase(ECDH_ES_A192KW,  A192CBC_HS384, validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> ec(P_384,  validDuration(), ECDH_ES_A192KW))),
                new EncryptionTestCase(ECDH_ES_A192KW,  A256CBC_HS512, validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> ec(P_521,  validDuration(), ECDH_ES_A192KW))),
                new EncryptionTestCase(ECDH_ES_A192KW,  XC20P,         validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> ec(P_521,  validDuration(), ECDH_ES_A192KW))),
                new EncryptionTestCase(ECDH_ES_A256KW,  A128GCM,       validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> ec(P_256,  validDuration(), ECDH_ES_A256KW))),
                new EncryptionTestCase(ECDH_ES_A256KW,  A192GCM,       validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> ec(P_384,  validDuration(), ECDH_ES_A256KW))),
                new EncryptionTestCase(ECDH_ES_A256KW,  A256GCM,       validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> ec(P_521,  validDuration(), ECDH_ES_A256KW))),
                new EncryptionTestCase(ECDH_ES_A256KW,  A128CBC_HS256, validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> ec(P_256,  validDuration(), ECDH_ES_A256KW))),
                new EncryptionTestCase(ECDH_ES_A256KW,  A192CBC_HS384, validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> ec(P_384,  validDuration(), ECDH_ES_A256KW))),
                new EncryptionTestCase(ECDH_ES_A256KW,  A256CBC_HS512, validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> ec(P_521,  validDuration(), ECDH_ES_A256KW))),
                new EncryptionTestCase(ECDH_ES_A256KW,  XC20P,         validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> ec(P_521,  validDuration(), ECDH_ES_A256KW))),
                new EncryptionTestCase(ECDH_1PU,        A128GCM,       validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> ec(P_256,  validDuration(), ECDH_1PU))),
                new EncryptionTestCase(ECDH_1PU,        A192GCM,       validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> ec(P_384,  validDuration(), ECDH_1PU))),
                new EncryptionTestCase(ECDH_1PU,        A256GCM,       validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> ec(P_521,  validDuration(), ECDH_1PU))),
                new EncryptionTestCase(ECDH_1PU,        A128CBC_HS256, validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> ec(P_256,  validDuration(), ECDH_1PU))),
                new EncryptionTestCase(ECDH_1PU,        A192CBC_HS384, validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> ec(P_384,  validDuration(), ECDH_1PU))),
                new EncryptionTestCase(ECDH_1PU,        A256CBC_HS512, validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> ec(P_521,  validDuration(), ECDH_1PU))),
                new EncryptionTestCase(ECDH_1PU,        XC20P,         validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> ec(P_521,  validDuration(), ECDH_1PU))),
//              new EncryptionTestCase(ECDH_1PU_A128KW, A128GCM,       validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> ec(P_256,  validDuration(), ECDH_1PU_A128KW))),
//              new EncryptionTestCase(ECDH_1PU_A128KW, A192GCM,       validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> ec(P_384,  validDuration(), ECDH_1PU_A128KW))),
//              new EncryptionTestCase(ECDH_1PU_A128KW, A256GCM,       validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> ec(P_521,  validDuration(), ECDH_1PU_A128KW))),
                new EncryptionTestCase(ECDH_1PU_A128KW, A128CBC_HS256, validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> ec(P_256,  validDuration(), ECDH_1PU_A128KW))),
                new EncryptionTestCase(ECDH_1PU_A128KW, A192CBC_HS384, validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> ec(P_384,  validDuration(), ECDH_1PU_A128KW))),
                new EncryptionTestCase(ECDH_1PU_A128KW, A256CBC_HS512, validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> ec(P_521,  validDuration(), ECDH_1PU_A128KW))),
//              new EncryptionTestCase(ECDH_1PU_A128KW, XC20P,         validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> ec(P_521,  validDuration(), ECDH_1PU_A128KW))),
//              new EncryptionTestCase(ECDH_1PU_A192KW, A128GCM,       validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> ec(P_256,  validDuration(), ECDH_1PU_A192KW))),
//              new EncryptionTestCase(ECDH_1PU_A192KW, A192GCM,       validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> ec(P_384,  validDuration(), ECDH_1PU_A192KW))),
//              new EncryptionTestCase(ECDH_1PU_A192KW, A256GCM,       validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> ec(P_521,  validDuration(), ECDH_1PU_A192KW))),
                new EncryptionTestCase(ECDH_1PU_A192KW, A128CBC_HS256, validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> ec(P_256,  validDuration(), ECDH_1PU_A192KW))),
                new EncryptionTestCase(ECDH_1PU_A192KW, A192CBC_HS384, validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> ec(P_384,  validDuration(), ECDH_1PU_A192KW))),
                new EncryptionTestCase(ECDH_1PU_A192KW, A256CBC_HS512, validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> ec(P_521,  validDuration(), ECDH_1PU_A192KW))),
//              new EncryptionTestCase(ECDH_1PU_A192KW, XC20P,         validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> ec(P_521,  validDuration(), ECDH_1PU_A192KW))),
//              new EncryptionTestCase(ECDH_1PU_A256KW, A128GCM,       validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> ec(P_256,  validDuration(), ECDH_1PU_A256KW))),
//              new EncryptionTestCase(ECDH_1PU_A256KW, A192GCM,       validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> ec(P_384,  validDuration(), ECDH_1PU_A256KW))),
//              new EncryptionTestCase(ECDH_1PU_A256KW, A256GCM,       validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> ec(P_521,  validDuration(), ECDH_1PU_A256KW))),
                new EncryptionTestCase(ECDH_1PU_A256KW, A128CBC_HS256, validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> ec(P_256,  validDuration(), ECDH_1PU_A256KW))),
                new EncryptionTestCase(ECDH_1PU_A256KW, A192CBC_HS384, validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> ec(P_384,  validDuration(), ECDH_1PU_A256KW))),
                new EncryptionTestCase(ECDH_1PU_A256KW, A256CBC_HS512, validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> ec(P_521,  validDuration(), ECDH_1PU_A256KW))),
//              new EncryptionTestCase(ECDH_1PU_A256KW, XC20P,         validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> ec(P_521,   validDuration(), ECDH_1PU_A256KW))),
                new EncryptionTestCase(A128GCMKW,       A128GCM,       validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> aes(B_128,  validDuration(), A128GCMKW))),
                new EncryptionTestCase(A192GCMKW,       A192GCM,       validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> aes(B_192,  validDuration(), A192GCMKW))),
                new EncryptionTestCase(A256GCMKW,       A256GCM,       validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> aes(B_256,  validDuration(), A256GCMKW))),
                new EncryptionTestCase(A128GCMKW,       A128CBC_HS256, validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> aes(B_128,  validDuration(), A128GCMKW))),
                new EncryptionTestCase(A192GCMKW,       A192CBC_HS384, validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> aes(B_192,  validDuration(), A192GCMKW))),
                new EncryptionTestCase(A256GCMKW,       A256CBC_HS512, validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> aes(B_256,  validDuration(), A256GCMKW))),
                new EncryptionTestCase(A256GCMKW,       XC20P,         validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> aes(B_256,  validDuration(), A256GCMKW))),
                new EncryptionTestCase(A128KW,          A128GCM,       validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> aes(B_128,  validDuration(), A128KW))),
                new EncryptionTestCase(A192KW,          A192GCM,       validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> aes(B_192,  validDuration(), A192KW))),
                new EncryptionTestCase(A256KW,          A256GCM,       validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> aes(B_256,  validDuration(), A256KW))),
                new EncryptionTestCase(A128KW,          A128CBC_HS256, validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> aes(B_128,  validDuration(), A128KW))),
                new EncryptionTestCase(A192KW,          A192CBC_HS384, validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> aes(B_192,  validDuration(), A192KW))),
                new EncryptionTestCase(A256KW,          A256CBC_HS512, validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> aes(B_256,  validDuration(), A256KW))),
                new EncryptionTestCase(A256KW,          XC20P,         validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> aes(B_256,  validDuration(), A256KW))),
                new EncryptionTestCase(DIR,             A128GCM,       validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> aes(B_128,  validDuration(), DIR))),
                new EncryptionTestCase(DIR,             A192GCM,       validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> aes(B_192,  validDuration(), DIR))),
                new EncryptionTestCase(DIR,             A256GCM,       validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> aes(B_256,  validDuration(), DIR))),
//              new EncryptionTestCase(DIR,             A128CBC_HS256, validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> Aes.B_128,  validDuration(), DIR))
//              new EncryptionTestCase(DIR,             A192CBC_HS384, validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> Aes.B_192,  validDuration(), DIR))),
//              new EncryptionTestCase(DIR,             A256CBC_HS512, validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> Aes.B_256,  validDuration(), DIR))),
//              new EncryptionTestCase(DIR,             XC20P,         validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> Aes.B_128,  validDuration(), DIR))),
//              new EncryptionTestCase(DIR,             XC20P,         validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> Aes.B_192,  validDuration(), DIR))),
                new EncryptionTestCase(DIR,             XC20P,         validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> aes(B_256,  validDuration(), DIR))),

                new EncryptionTestCase(RSA1_5,         A128GCM,       validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> rsa(B_2048, validDuration(), NULL))),
                new EncryptionTestCase(RSA1_5,          A192GCM,       validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> rsa(B_2048, validDuration(), NULL))),
                new EncryptionTestCase(RSA1_5,          A256GCM,       validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> rsa(B_2048, validDuration(), NULL))),
                new EncryptionTestCase(RSA1_5,          A128CBC_HS256, validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> rsa(B_2048, validDuration(), NULL))),
                new EncryptionTestCase(RSA1_5,          A192CBC_HS384, validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> rsa(B_2048, validDuration(), NULL))),
                new EncryptionTestCase(RSA1_5,          A256CBC_HS512, validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> rsa(B_2048, validDuration(), NULL))),
                new EncryptionTestCase(RSA1_5,          XC20P,         validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> rsa(B_2048, validDuration(), NULL))),
                new EncryptionTestCase(RSA_OAEP,        A128GCM,       validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> rsa(B_2048, validDuration(), NULL))),
                new EncryptionTestCase(RSA_OAEP,        A192GCM,       validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> rsa(B_2048, validDuration(), NULL))),
                new EncryptionTestCase(RSA_OAEP,        A256GCM,       validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> rsa(B_2048, validDuration(), NULL))),
                new EncryptionTestCase(RSA_OAEP,        A128CBC_HS256, validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> rsa(B_2048, validDuration(), NULL))),
                new EncryptionTestCase(RSA_OAEP,        A192CBC_HS384, validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> rsa(B_2048, validDuration(), NULL))),
                new EncryptionTestCase(RSA_OAEP,        A256CBC_HS512, validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> rsa(B_2048, validDuration(), NULL))),
                new EncryptionTestCase(RSA_OAEP,        XC20P,         validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> rsa(B_2048, validDuration(), NULL))),
                new EncryptionTestCase(RSA_OAEP_256,    A128GCM,       validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> rsa(B_2048, validDuration(), NULL))),
                new EncryptionTestCase(RSA_OAEP_384,    A192GCM,       validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> rsa(B_2048, validDuration(), NULL))),
                new EncryptionTestCase(RSA_OAEP_512,    A256GCM,       validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> rsa(B_2048, validDuration(), NULL))),
                new EncryptionTestCase(RSA_OAEP_256,    A128CBC_HS256, validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> rsa(B_2048, validDuration(), NULL))),
                new EncryptionTestCase(RSA_OAEP_384,    A192CBC_HS384, validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> rsa(B_2048, validDuration(), NULL))),
                new EncryptionTestCase(RSA_OAEP_512,    A256CBC_HS512, validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> rsa(B_2048, validDuration(), NULL))),
                new EncryptionTestCase(RSA_OAEP_512,    XC20P,         validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> rsa(B_2048, validDuration(), NULL))),
                new EncryptionTestCase(ECDH_ES,         A128GCM,       validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> ec(P_256,   validDuration(), NULL))),
                new EncryptionTestCase(ECDH_ES,         A192GCM,       validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> ec(P_384,   validDuration(), NULL))),
                new EncryptionTestCase(ECDH_ES,         A256GCM,       validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> ec(P_521,   validDuration(), NULL))),
                new EncryptionTestCase(ECDH_ES,         A128CBC_HS256, validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> ec(P_256,   validDuration(), NULL))),
                new EncryptionTestCase(ECDH_ES,         A192CBC_HS384, validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> ec(P_384,   validDuration(), NULL))),
                new EncryptionTestCase(ECDH_ES,         A256CBC_HS512, validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> ec(P_521,   validDuration(), NULL))),
                new EncryptionTestCase(ECDH_ES,         XC20P,         validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> ec(P_521,   validDuration(), NULL))),
                new EncryptionTestCase(ECDH_ES_A128KW,  A128GCM,       validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> ec(P_256,   validDuration(), NULL))),
                new EncryptionTestCase(ECDH_ES_A128KW,  A192GCM,       validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> ec(P_384,   validDuration(), NULL))),
                new EncryptionTestCase(ECDH_ES_A128KW,  A256GCM,       validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> ec(P_521,   validDuration(), NULL))),
                new EncryptionTestCase(ECDH_ES_A128KW,  A128CBC_HS256, validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> ec(P_256,   validDuration(), NULL))),
                new EncryptionTestCase(ECDH_ES_A128KW,  A192CBC_HS384, validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> ec(P_384,   validDuration(), NULL))),
                new EncryptionTestCase(ECDH_ES_A128KW,  A256CBC_HS512, validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> ec(P_521,   validDuration(), NULL))),
                new EncryptionTestCase(ECDH_ES_A128KW,  XC20P,         validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> ec(P_521,   validDuration(), NULL))),
                new EncryptionTestCase(ECDH_ES_A192KW,  A128GCM,       validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> ec(P_256,   validDuration(), NULL))),
                new EncryptionTestCase(ECDH_ES_A192KW,  A192GCM,       validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> ec(P_384,   validDuration(), NULL))),
                new EncryptionTestCase(ECDH_ES_A192KW,  A256GCM,       validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> ec(P_521,   validDuration(), NULL))),
                new EncryptionTestCase(ECDH_ES_A192KW,  A128CBC_HS256, validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> ec(P_256,   validDuration(), NULL))),
                new EncryptionTestCase(ECDH_ES_A192KW,  A192CBC_HS384, validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> ec(P_384,   validDuration(), NULL))),
                new EncryptionTestCase(ECDH_ES_A192KW,  A256CBC_HS512, validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> ec(P_521,   validDuration(), NULL))),
                new EncryptionTestCase(ECDH_ES_A192KW,  XC20P,         validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> ec(P_521,   validDuration(), NULL))),
                new EncryptionTestCase(ECDH_ES_A256KW,  A128GCM,       validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> ec(P_256,   validDuration(), NULL))),
                new EncryptionTestCase(ECDH_ES_A256KW,  A192GCM,       validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> ec(P_384,   validDuration(), NULL))),
                new EncryptionTestCase(ECDH_ES_A256KW,  A256GCM,       validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> ec(P_521,   validDuration(), NULL))),
                new EncryptionTestCase(ECDH_ES_A256KW,  A128CBC_HS256, validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> ec(P_256,   validDuration(), NULL))),
                new EncryptionTestCase(ECDH_ES_A256KW,  A192CBC_HS384, validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> ec(P_384,   validDuration(), NULL))),
                new EncryptionTestCase(ECDH_ES_A256KW,  A256CBC_HS512, validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> ec(P_521,   validDuration(), NULL))),
                new EncryptionTestCase(ECDH_ES_A256KW,  XC20P,         validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> ec(P_521,   validDuration(), NULL))),
                new EncryptionTestCase(ECDH_1PU,        A128GCM,       validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> ec(P_256,   validDuration(), NULL))),
                new EncryptionTestCase(ECDH_1PU,        A192GCM,       validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> ec(P_384,   validDuration(), NULL))),
                new EncryptionTestCase(ECDH_1PU,        A256GCM,       validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> ec(P_521,   validDuration(), NULL))),
                new EncryptionTestCase(ECDH_1PU,        A128CBC_HS256, validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> ec(P_256,   validDuration(), NULL))),
                new EncryptionTestCase(ECDH_1PU,        A192CBC_HS384, validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> ec(P_384,   validDuration(), NULL))),
                new EncryptionTestCase(ECDH_1PU,        A256CBC_HS512, validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> ec(P_521,   validDuration(), NULL))),
                new EncryptionTestCase(ECDH_1PU,        XC20P,         validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> ec(P_521,   validDuration(), NULL))),
//              new EncryptionTestCase(ECDH_1PU_A128KW, A128GCM,       validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> ec(P_256,   validDuration(), NULL))),
//              new EncryptionTestCase(ECDH_1PU_A128KW, A192GCM,       validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> ec(P_384,   validDuration(), NULL))),
//              new EncryptionTestCase(ECDH_1PU_A128KW, A256GCM,       validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> ec(P_521,   validDuration(), NULL))),
                new EncryptionTestCase(ECDH_1PU_A128KW, A128CBC_HS256, validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> ec(P_256,   validDuration(), NULL))),
                new EncryptionTestCase(ECDH_1PU_A128KW, A192CBC_HS384, validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> ec(P_384,   validDuration(), NULL))),
                new EncryptionTestCase(ECDH_1PU_A128KW, A256CBC_HS512, validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> ec(P_521,   validDuration(), NULL))),
//              new EncryptionTestCase(ECDH_1PU_A128KW, XC20P,         validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> ec(P_521,   validDuration(), NULL))),
//              new EncryptionTestCase(ECDH_1PU_A192KW, A128GCM,       validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> ec(P_256,   validDuration(), NULL))),
//              new EncryptionTestCase(ECDH_1PU_A192KW, A192GCM,       validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> ec(P_384,   validDuration(), NULL))),
//              new EncryptionTestCase(ECDH_1PU_A192KW, A256GCM,       validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> ec(P_521,   validDuration(), NULL))),
                new EncryptionTestCase(ECDH_1PU_A192KW, A128CBC_HS256, validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> ec(P_256,   validDuration(), NULL))),
                new EncryptionTestCase(ECDH_1PU_A192KW, A192CBC_HS384, validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> ec(P_384,   validDuration(), NULL))),
                new EncryptionTestCase(ECDH_1PU_A192KW, A256CBC_HS512, validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> ec(P_521,   validDuration(), NULL))),
//              new EncryptionTestCase(ECDH_1PU_A192KW, XC20P,         validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> ec(P_521,   validDuration(), NULL))),
//              new EncryptionTestCase(ECDH_1PU_A256KW, A128GCM,       validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> ec(P_256,   validDuration(), NULL))),
//              new EncryptionTestCase(ECDH_1PU_A256KW, A192GCM,       validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> ec(P_384,   validDuration(), NULL))),
//              new EncryptionTestCase(ECDH_1PU_A256KW, A256GCM,       validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> ec(P_521,   validDuration(), NULL))),
                new EncryptionTestCase(ECDH_1PU_A256KW, A128CBC_HS256, validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> ec(P_256,   validDuration(), NULL))),
                new EncryptionTestCase(ECDH_1PU_A256KW, A192CBC_HS384, validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> ec(P_384,   validDuration(), NULL))),
                new EncryptionTestCase(ECDH_1PU_A256KW, A256CBC_HS512, validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> ec(P_521,   validDuration(), NULL))),
//              new EncryptionTestCase(ECDH_1PU_A256KW, XC20P,         validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> ec(P_521,   validDuration(), NULL))),
                new EncryptionTestCase(A128GCMKW,       A128GCM,       validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> aes(B_128,  validDuration(), NULL))),
                new EncryptionTestCase(A192GCMKW,       A192GCM,       validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> aes(B_192,  validDuration(), NULL))),
                new EncryptionTestCase(A256GCMKW,       A256GCM,       validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> aes(B_256,  validDuration(), NULL))),
                new EncryptionTestCase(A128GCMKW,       A128CBC_HS256, validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> aes(B_128,  validDuration(), NULL))),
                new EncryptionTestCase(A192GCMKW,       A192CBC_HS384, validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> aes(B_192,  validDuration(), NULL))),
                new EncryptionTestCase(A256GCMKW,       A256CBC_HS512, validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> aes(B_256,  validDuration(), NULL))),
                new EncryptionTestCase(A256GCMKW,       XC20P,         validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> aes(B_256,  validDuration(), NULL))),
                new EncryptionTestCase(A128KW,          A128GCM,       validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> aes(B_128,  validDuration(), NULL))),
                new EncryptionTestCase(A192KW,          A192GCM,       validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> aes(B_192,  validDuration(), NULL))),
                new EncryptionTestCase(A256KW,          A256GCM,       validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> aes(B_256,  validDuration(), NULL))),
                new EncryptionTestCase(A128KW,          A128CBC_HS256, validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> aes(B_128,  validDuration(), NULL))),
                new EncryptionTestCase(A192KW,          A192CBC_HS384, validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> aes(B_192,  validDuration(), NULL))),
                new EncryptionTestCase(A256KW,          A256CBC_HS512, validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> aes(B_256,  validDuration(), NULL))),
                new EncryptionTestCase(A256KW,          XC20P,         validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> aes(B_256,  validDuration(), NULL))),
                new EncryptionTestCase(DIR,             A128GCM,       validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> aes(B_128,  validDuration(), NULL))),
                new EncryptionTestCase(DIR,             A192GCM,       validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> aes(B_192,  validDuration(), NULL))),
                new EncryptionTestCase(DIR,             A256GCM,       validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> aes(B_256,  validDuration(), NULL))),
//              new EncryptionTestCase(DIR,             A128CBC_HS256, validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> Aes.B_128,  validDuration(), NULL))),
//              new EncryptionTestCase(DIR,             A192CBC_HS384, validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> Aes.B_192,  validDuration(), NULL))),
//              new EncryptionTestCase(DIR,             A256CBC_HS512, validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> Aes.B_256,  validDuration(), NULL))),
//              new EncryptionTestCase(DIR,             XC20P,         validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> Aes.B_128,  validDuration(), NULL))),
//              new EncryptionTestCase(DIR,             XC20P,         validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> Aes.B_192,  validDuration(), NULL))),
                new EncryptionTestCase(DIR,             XC20P,         validJwtClaimsSet(), true, true, ThreadUtil.supplyAsync(() -> aes(B_256,  validDuration(), NULL)))
            );
        }
    }

    private static void assertEqualJwts(final SignedJWT expectedSignedJwt, final SignedJWT actualSignedJwt) throws ParseException {
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

    private static void assertEqualJwts(final EncryptedJWT expectedEncryptedJwt, final EncryptedJWT actualEncryptedJwt) throws ParseException {
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

    @NoArgsConstructor(access=AccessLevel.PRIVATE)
    public final static class JAlg {
        public static final Algorithm NULL = null;
    }
    @NoArgsConstructor(access=AccessLevel.PRIVATE)
    public final static class Bits {
        public static final int B_128  = 128; // strength  64-bits
        public static final int B_192  = 192; // strength  96-bits
        public static final int B_256  = 256; // strength 128-bits
        public static final int B_384  = 384; // strength 192-bits
        public static final int B_512  = 512; // strength 256-bits
        public static final int B_2048  = 2048; // strength ~112-bits
        public static final int B_3072  = 3072; // strength ~128-bits
        public static final int B_4096  = 4096; // strength ~???-bits
        public static final int B_5120  = 5120; // strength ~???-bits
        public static final int B_6144  = 6144; // strength ~???-bits
    }
}
