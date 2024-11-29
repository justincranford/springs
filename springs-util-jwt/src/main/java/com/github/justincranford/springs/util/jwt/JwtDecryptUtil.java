package com.github.justincranford.springs.util.jwt;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEDecrypter;
import com.nimbusds.jose.KeyLengthException;
import com.nimbusds.jose.crypto.AESDecrypter;
import com.nimbusds.jose.crypto.DirectDecrypter;
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
    public static JWEDecrypter jweDecryptor(final JWK jwk, final JWEAlgorithm alg) throws JOSEException {
        if (jwk instanceof OctetSequenceKey) {
            return aesDecryptor(jwk.toOctetSequenceKey(), alg, AES_ENCRYPT_DECRYPT_PROVIDER);
        } else if (jwk instanceof ECKey) {
            return ecDecryptor(jwk.toECKey(), alg, EC_ENCRYPT_DECRYPT_PROVIDER);
        } else if (jwk instanceof RSAKey) {
            return rsaDecryptor(jwk.toRSAKey(), alg, RSA_ENCRYPT_DECRYPT_PROVIDER);
        }
        throw new JOSEException("Unsupported key type for decryption");
    }

    public static JWEDecrypter aesDecryptor(final OctetSequenceKey octetSequenceKey, final JWEAlgorithm alg, final Provider provider) throws KeyLengthException {
        if (JWEAlgorithm.DIR.equals(alg)) {
            return new DirectDecrypter(octetSequenceKey);
        }
        return new AESDecrypter(octetSequenceKey);
    }
    public static ECDHDecrypter ecDecryptor(final ECKey ecKey, final JWEAlgorithm alg, final Provider provider) throws JOSEException {
        return new ECDHDecrypter(ecKey);
    }
    public static RSADecrypter rsaDecryptor(final RSAKey rsaKey, final JWEAlgorithm alg, final Provider provider) throws JOSEException {
        return new RSADecrypter(rsaKey);
    }

    public static EncryptedJWT decrypt(final EncryptedJWT toBeDecryptedJWT, final JWEDecrypter jweDecrypter) throws JOSEException, ParseException {
        toBeDecryptedJWT.decrypt(jweDecrypter);
        return toBeDecryptedJWT;
    }
}
