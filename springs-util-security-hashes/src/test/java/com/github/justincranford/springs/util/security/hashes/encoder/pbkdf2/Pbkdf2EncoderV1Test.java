package com.github.justincranford.springs.util.security.hashes.encoder.pbkdf2;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.HashSet;
import java.util.Set;
import java.util.function.Supplier;

import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;

import com.github.justincranford.springs.util.basic.Base64Util;
import com.github.justincranford.springs.util.basic.SecureRandomUtil;
import com.github.justincranford.springs.util.security.hashes.encoder.model.HashEncodeDecode;

import lombok.extern.slf4j.Slf4j;

@Slf4j
@SuppressWarnings({"nls", "static-method"})
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
public class Pbkdf2EncoderV1Test {
	private static final int REPEATS = 2;

	@Test
	public void testPbkdf2ConstantSalt() {
		final Supplier<byte[]> saltSupplier = () -> new byte[16];
		final Pbkdf2EncoderV1 parameters = new Pbkdf2EncoderV1(Pbkdf2Algorithm.PBKDF2WithHmacSHA256, 1, 32, HashEncodeDecode.STD_CB_NONE);
		Set<String> encodedHashes = computePbkdf2(REPEATS, parameters, "Hello.World@example.com", saltSupplier);
		assertThat(encodedHashes.size()).isEqualTo(1);
	}

	@Test
	public void testPbkdf2RandomSalt() {
		final Supplier<byte[]> saltSupplier = () -> SecureRandomUtil.randomBytes(16);
		final Pbkdf2EncoderV1 parameters = new Pbkdf2EncoderV1(Pbkdf2Algorithm.PBKDF2WithHmacSHA256, 1, 32, HashEncodeDecode.STD_CB_NONE);
		Set<String> encodedHashes = computePbkdf2(REPEATS, parameters, "P@ssw0rd", saltSupplier);
		assertThat(encodedHashes.size()).isEqualTo(REPEATS);
	}

	private Set<String> computePbkdf2(final int repeats, final Pbkdf2EncoderV1 parameters, final String inputBytes, final Supplier<byte[]> saltSupplier) {
		final Set<String> encodedHashes = new HashSet<>();
		for (int i = 0; i < repeats; i++) {
			final byte[] hashBytes = parameters.computeHash(saltSupplier.get(), inputBytes);
			encodedHashes.add(Base64Util.Constants.STD_ENCODER.encodeToString(hashBytes));
		}
		return encodedHashes;
	}
}
