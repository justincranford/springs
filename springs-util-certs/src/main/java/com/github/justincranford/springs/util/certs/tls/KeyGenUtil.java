package com.github.justincranford.springs.util.certs.tls;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;
import java.util.List;
import java.util.stream.IntStream;

import com.github.justincranford.springs.util.basic.util.SecureRandomUtil;

@SuppressWarnings("nls")
public class KeyGenUtil {
	public static List<KeyPair> generateKeyPairs(final int count, final String algorithm) throws Exception {
		final KeyPairGenerator keyPairGenerator = createKeyPairGenerator(algorithm);
		return IntStream.rangeClosed(1, count).parallel().boxed().map(i -> keyPairGenerator.generateKeyPair()).toList();
	}

	private static KeyPairGenerator createKeyPairGenerator(final String algorithm) throws Exception {
		final KeyPairGenerator keyPairGenerator;
		if (algorithm == null) {
			// fall through to exception
        } else if (algorithm.startsWith("RSA-")) {
        	final int rsaKeyLengthBits = Integer.parseInt(algorithm.substring(4));
        	keyPairGenerator = KeyPairGenerator.getInstance("RSA", Security.getProvider("SunRsaSign"));
			keyPairGenerator.initialize(rsaKeyLengthBits, SecureRandomUtil.SECURE_RANDOM);
        	return keyPairGenerator;
        } else if (algorithm.startsWith("EC")) {
        	final String ecCurveName = switch (algorithm) {
			    case "EC-P256" -> "secp256r1";
			    case "EC-P384" -> "secp384r1";
			    case "EC-P521" -> "secp521r1";
			    default -> throw new IllegalArgumentException("Unsupported algorithm " + algorithm);
			};
        	keyPairGenerator = KeyPairGenerator.getInstance("EC", Security.getProvider("SunEC"));
			keyPairGenerator.initialize(new ECGenParameterSpec(ecCurveName), SecureRandomUtil.SECURE_RANDOM);
        	return keyPairGenerator;
        } else if (algorithm.equals("Ed25519")) {
        	// Caveat: Spring PEM_PARSERS does not have an PEM parser for Ed25519 (BEGIN PRIVATE KEY), so this doesn't work yet
        	keyPairGenerator = KeyPairGenerator.getInstance("Ed25519", Security.getProvider("SunEC"));
        	return keyPairGenerator;
        }
    	throw new IllegalArgumentException("Unsupported server.ssl.auto-config.algorithm=" + algorithm);
	}
}
