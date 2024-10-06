package com.github.justincranford.springs.util.certs.util;

import java.security.Key;
import java.security.Provider;
import java.security.Security;
import java.security.interfaces.ECKey;
import java.security.interfaces.RSAKey;

@SuppressWarnings("nls")
public class SignUtil {
	public static record ProviderAndAlgorithm(Provider provider, String algorithm) { }
	public static ProviderAndAlgorithm toProviderAndAlgorithm(final Key key) {
		if (key instanceof RSAKey rsaKey) {
			final int keyLengthBits = rsaKey.getModulus().bitCount();
			if (keyLengthBits < 1024) {
				throw new IllegalArgumentException("Unsupported RSA modulus bit length " + keyLengthBits);
			}
			final Provider provider = Security.getProvider("SunRsaSign");
			if (keyLengthBits < 4096) {
				return new ProviderAndAlgorithm(provider, "SHA256withRSA");
			} else if (keyLengthBits < 5120) {
				return new ProviderAndAlgorithm(provider, "SHA384withRSA");
			} else {
				return new ProviderAndAlgorithm(provider, "SHA512withRSA");
			}
		}
		if (key instanceof ECKey ecKey) {
			final int keyLengthBits = ecKey.getParams().getCurve().getField().getFieldSize();
			if (keyLengthBits < 256) {
				throw new IllegalArgumentException("Unsupported RSA modulus bit length " + keyLengthBits);
			}
			final Provider provider = Security.getProvider("SunEC");
			if (keyLengthBits < 384) {
				return new ProviderAndAlgorithm(provider, "SHA256withECDSA");
			} else if (keyLengthBits < 512) {
				return new ProviderAndAlgorithm(provider, "SHA384withECDSA");
			} else {
				return new ProviderAndAlgorithm(provider, "SHA512withECDSA");
			}
		}
		throw new IllegalArgumentException("Unsupported key " + key.getAlgorithm());
	}
}
