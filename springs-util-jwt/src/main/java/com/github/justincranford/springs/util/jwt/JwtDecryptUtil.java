package com.github.justincranford.springs.util.jwt;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEDecrypter;
import com.nimbusds.jose.KeyLengthException;
import com.nimbusds.jose.crypto.AESDecrypter;
import com.nimbusds.jose.crypto.ECDHDecrypter;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.EncryptedJWT;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;

import java.security.Provider;
import java.text.ParseException;

import static com.github.justincranford.springs.util.jwt.ProviderUtil.AES_ENCRYPT_DECRYPT_PROVIDER;
import static com.github.justincranford.springs.util.jwt.ProviderUtil.EC_ENCRYPT_DECRYPT_PROVIDER;
import static com.github.justincranford.springs.util.jwt.ProviderUtil.RSA_ENCRYPT_DECRYPT_PROVIDER;

@NoArgsConstructor(access=AccessLevel.PRIVATE)
public final class JwtDecryptUtil {
    public static JWEDecrypter jweDecrypter(final JWK jwk) throws JOSEException {
        if (jwk instanceof OctetSequenceKey) {
            return aesDecryptor(jwk.toOctetSequenceKey(), AES_ENCRYPT_DECRYPT_PROVIDER);
        } else if (jwk instanceof ECKey) {
            return ecDecryptor(jwk.toECKey(), EC_ENCRYPT_DECRYPT_PROVIDER);
        } else if (jwk instanceof RSAKey) {
            return rsaDecryptor(jwk.toRSAKey(), RSA_ENCRYPT_DECRYPT_PROVIDER);
        }
        throw new JOSEException("Unsupported key type for decryption");
    }

    public static AESDecrypter aesDecryptor(final OctetSequenceKey octetSequenceKey, final Provider provider) throws KeyLengthException {
        return new AESDecrypter(octetSequenceKey);
    }
    public static ECDHDecrypter ecDecryptor(final ECKey ecKey, final Provider provider) throws JOSEException {
        return new ECDHDecrypter(ecKey);
    }
    public static RSADecrypter rsaDecryptor(final RSAKey rsaKey, final Provider provider) throws JOSEException {
        return new RSADecrypter(rsaKey);
    }

    public static EncryptedJWT decrypt(final JWEDecrypter jweDecrypter, final EncryptedJWT toBeDecryptedJWT) throws JOSEException, ParseException {
        toBeDecryptedJWT.decrypt(jweDecrypter);
        return toBeDecryptedJWT;
    }
}
