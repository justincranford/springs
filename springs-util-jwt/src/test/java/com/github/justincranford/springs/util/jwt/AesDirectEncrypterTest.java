package com.github.justincranford.springs.util.jwt;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEDecrypter;
import com.nimbusds.jose.JWEEncrypter;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.crypto.DirectDecrypter;
import com.nimbusds.jose.crypto.DirectEncrypter;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.jwk.gen.OctetSequenceKeyGenerator;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWTClaimsSet;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.junit.jupiter.MockitoExtension;

import java.text.ParseException;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;

@ExtendWith(MockitoExtension.class)
@Slf4j
class AesDirectEncrypterTest {
    public static final JWTClaimsSet JWT_CLAIMS_SET = new JWTClaimsSet.Builder().claim("k", "v").build();

    public record Args(EncryptionMethod aesEnc, int aesBitLen) { }
    static Stream<Args> args() throws JOSEException {
        return Stream.of(
            new Args(EncryptionMethod.A128GCM,       128), // Success
            new Args(EncryptionMethod.A192GCM,       192), // Success
            new Args(EncryptionMethod.A256GCM,       256), // Success
            new Args(EncryptionMethod.A128CBC_HS256, 128), // JOSEException: The A128CBC-HS256 encryption method or key size is not supported by the JWE encrypter: Supported methods: [A128GCM]
            new Args(EncryptionMethod.A192CBC_HS384, 192), // JOSEException: The A192CBC-HS384 encryption method or key size is not supported by the JWE encrypter: Supported methods: [A192GCM]
            new Args(EncryptionMethod.A256CBC_HS512, 256)  // JOSEException: The A256CBC-HS512 encryption method or key size is not supported by the JWE encrypter: Supported methods: [XC20P, A256GCM, A128CBC-HS256, A128CBC+HS256]
        );
    }

    @ParameterizedTest
    @MethodSource("args")
    public void testAesDirectEncrypter(final Args args) throws JOSEException, ParseException {
        final OctetSequenceKey aesJwk       = new OctetSequenceKeyGenerator(args.aesBitLen).generate();
        final JWEHeader        jweHeader    = new JWEHeader.Builder(JWEAlgorithm.DIR, args.aesEnc).type(JOSEObjectType.JWT).build();
        final JWEEncrypter     jweEncrypter = new DirectEncrypter(aesJwk);
        final EncryptedJWT     encryptedJwt = new EncryptedJWT(jweHeader, JWT_CLAIMS_SET);
        log.info("EncryptedJWT:\nHeader: {}\nClaims: {}", encryptedJwt.getHeader(), encryptedJwt.getJWTClaimsSet());
        assertDoesNotThrow(() -> encryptedJwt.encrypt(jweEncrypter)); // Unexpected exception from JWEObject.ensureJWEEncrypterSupport() for A###CBC_HS### encryption methods

        final String       serializedEncryptedJwt = encryptedJwt.serialize();
        final EncryptedJWT decryptedJwt           = EncryptedJWT.parse(serializedEncryptedJwt);
        final JWEDecrypter jweDecryptor           = new DirectDecrypter(aesJwk);
        decryptedJwt.decrypt(jweDecryptor);
        log.info("DecryptedJWT:\nHeader: {}\nClaims: {}", decryptedJwt.getHeader(), decryptedJwt.getJWTClaimsSet());

        assertEqualsEncryptedJwts(encryptedJwt, decryptedJwt);
    }

    private static void assertEqualsEncryptedJwts(final EncryptedJWT expectedEncryptedJwt, final EncryptedJWT actualEncryptedJwt) throws ParseException {
        final JWEHeader    expectedJweHeader    = expectedEncryptedJwt.getHeader();
        final JWTClaimsSet expectedJwtClaimsSet = expectedEncryptedJwt.getJWTClaimsSet();
        final Base64URL    expectedEncryptedKey = expectedEncryptedJwt.getEncryptedKey();
        final Base64URL    expectedIV           = expectedEncryptedJwt.getIV();
        final Base64URL    expectedAuthTag      = expectedEncryptedJwt.getAuthTag();

        final JWEHeader    actualJweHeader      = actualEncryptedJwt.getHeader();
        final JWTClaimsSet actualJwtClaimsSet   = actualEncryptedJwt.getJWTClaimsSet();
        final Base64URL    actualEncryptedKey   = actualEncryptedJwt.getEncryptedKey();
        final Base64URL    actualIV             = actualEncryptedJwt.getIV();
        final Base64URL    actualAuthTag        = actualEncryptedJwt.getAuthTag();

        assertEquals(expectedJweHeader.toJSONObject(),    actualJweHeader.toJSONObject(),    "JWE headers are not equal");
        assertEquals(expectedJwtClaimsSet.toJSONObject(), actualJwtClaimsSet.toJSONObject(), "JWT claims are not equal");
        assertEquals(expectedEncryptedKey,                actualEncryptedKey,                "JWE encrypted keys are not equal");
        assertEquals(expectedIV,                          actualIV,                          "JWE IVs are not equal");
        assertEquals(expectedAuthTag,                     actualAuthTag,                     "JWE auth tags are not equal");
    }
}
