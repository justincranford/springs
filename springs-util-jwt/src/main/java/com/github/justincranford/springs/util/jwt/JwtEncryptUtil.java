package com.github.justincranford.springs.util.jwt;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEEncrypter;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.KeyLengthException;
import com.nimbusds.jose.crypto.AESEncrypter;
import com.nimbusds.jose.crypto.ECDHEncrypter;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWTClaimsSet;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;

import java.security.Provider;
import java.time.Duration;
import java.util.List;
import java.util.Set;

import static com.github.justincranford.springs.util.jwt.JwtContentUtil.jweHeader;
import static com.github.justincranford.springs.util.jwt.JwtContentUtil.jwtClaimsSet;
import static com.github.justincranford.springs.util.jwt.ProviderUtil.AES_ENCRYPT_DECRYPT_PROVIDER;
import static com.github.justincranford.springs.util.jwt.ProviderUtil.EC_ENCRYPT_DECRYPT_PROVIDER;
import static com.github.justincranford.springs.util.jwt.ProviderUtil.RSA_ENCRYPT_DECRYPT_PROVIDER;

@NoArgsConstructor(access=AccessLevel.PRIVATE)
public final class JwtEncryptUtil {
    public static JWEEncrypter jweEncrypter(final JWK jwk) throws JOSEException {
        if (jwk instanceof OctetSequenceKey) {
            return aesEncryptor(jwk.toOctetSequenceKey(), AES_ENCRYPT_DECRYPT_PROVIDER);
        } else if (jwk instanceof ECKey) {
            return ecEncryptor(jwk.toECKey(), EC_ENCRYPT_DECRYPT_PROVIDER);
        } else if (jwk instanceof RSAKey) {
            return rsaEncryptor(jwk.toRSAKey(), RSA_ENCRYPT_DECRYPT_PROVIDER);
        }
        throw new JOSEException("Unsupported key type for encryption");
    }

    public static AESEncrypter aesEncryptor(final OctetSequenceKey octetSequenceKey, final Provider provider) throws KeyLengthException {
        return new AESEncrypter(octetSequenceKey);
    }
    public static ECDHEncrypter ecEncryptor(final ECKey ecKey, final Provider provider) throws JOSEException {
        return new ECDHEncrypter(ecKey);
    }
    public static RSAEncrypter rsaEncryptor(final RSAKey rsaKey, final Provider provider) throws JOSEException {
        return new RSAEncrypter(rsaKey);
    }

    public static EncryptedJWT encrypt(final JWK jwk, final EncryptionMethod enc, final String iss, final List<String> aud, final String sub, final Set<String> scopes, final Duration duration) throws Exception {
        final JWEHeader    jweHeader    = jweHeader(jwk, enc);
        final JWTClaimsSet jwtClaimsSet = jwtClaimsSet(iss, aud, sub, duration, scopes);
        final JWEEncrypter jweEncrypter = jweEncrypter(jwk);
        return encrypt(jweHeader, jwtClaimsSet, jweEncrypter);
    }

    public static EncryptedJWT encrypt(final JWEHeader jweHeader, final JWTClaimsSet jwtClaimsSet, final JWEEncrypter jweEncrypter) throws JOSEException {
        final EncryptedJWT toBeEncryptedJWT = new EncryptedJWT(jweHeader, jwtClaimsSet);
        return encrypt(toBeEncryptedJWT, jweEncrypter);
    }

    private static EncryptedJWT encrypt(final EncryptedJWT toBeEncryptedJWT, final JWEEncrypter jweEncrypter) throws JOSEException {
        toBeEncryptedJWT.encrypt(jweEncrypter);
        return toBeEncryptedJWT;
    }
}
