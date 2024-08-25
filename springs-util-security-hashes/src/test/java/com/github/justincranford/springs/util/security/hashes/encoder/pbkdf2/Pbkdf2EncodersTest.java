package com.github.justincranford.springs.util.security.hashes.encoder.pbkdf2;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import java.util.Map;
import java.util.stream.IntStream;

import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.springframework.security.crypto.password.DelegatingPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import lombok.extern.slf4j.Slf4j;

@Slf4j
@SuppressWarnings({"nls", "boxing", "static-method"})
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
public class Pbkdf2EncodersTest {
	private static final int REPEATS = 3;

	private static final String keyEncodersDefault = "derived";
	private static final Map<String, PasswordEncoder> keyEncodersMap = Map.of(
		"derived", Pbkdf2Encoder.DerivedSalt.DEFAULT1,
		"constant", Pbkdf2Encoder.ConstantSalt.DEFAULT1
	);
	private static final DelegatingPasswordEncoder keyEncoders = new DelegatingPasswordEncoder(
		keyEncodersDefault,
		keyEncodersMap
	);

	private static final String valueEncodersDefault = "random";
	private static final Map<String, PasswordEncoder> valueEncodersMap = Map.of(
		"random", Pbkdf2Encoder.RandomSalt.DEFAULT1
	);
	private static final DelegatingPasswordEncoder valueEncoders = new DelegatingPasswordEncoder(
		valueEncodersDefault,
		valueEncodersMap
	);

	@Order(1)
	@Test
	void testTopLevelKeyEncoders() {
		helper(keyEncoders, keyEncodersDefault, "Hello.World@example.com");
	}

	@Order(2)
	@Test
	void testTopLevelValueEncoders() {
		helper(valueEncoders, valueEncodersDefault, "P@ssw0rd");
	}

	@Order(3)
	@Test
	void testEachIndividualKeyEncoder() {
		keyEncodersMap.values().forEach(keyEncoder -> helper(keyEncoder, "n/a",  "Hello.World@example.com"));
	}

	@Order(4)
	@Test
	void testEachIndividualValueEncoder() {
		valueEncodersMap.values().forEach(valueEncoder -> helper(valueEncoder, "n/a", "P@ssw0rd"));
	}

	private static void helper(final PasswordEncoder passwordEncoder, final String idForEncode, final String raw) {
		// original password is encoded multiple times, each one with different (random) salt, and produces different hash
		final List<String> encodeds = IntStream.rangeClosed(1, REPEATS).boxed().map(i -> passwordEncoder.encode(raw)).toList();
//		log.info("encodeds:\n{}", encodeds.stream().map(s -> "\n  "+s).toList().toString().replace("]", "\n]"));

		// original password matches all encoded hashes+parameters
		for (final String encoded : encodeds) {
			final String className = passwordEncoder.getClass().getSimpleName();
			if (passwordEncoder instanceof DelegatingPasswordEncoder) { // DelegatingPasswordEncoder => KeyEncoders, ValueEncoders
				assertThat(encoded).startsWith("{" + idForEncode + "}");
			} else { // PasswordEncoder => KeyEncoder, ValueEncoder
				assertThat(encoded).doesNotStartWith("{");
			}
			final boolean matches = passwordEncoder.matches(raw, encoded);
			final boolean upgradeEncoding = passwordEncoder.upgradeEncoding(encoded);
			log.info("class: {}, idForEncode: {}, matches: {}, upgradeEncoding: {}, raw: {}, encoded: {}", className, idForEncode, matches, upgradeEncoding, raw, encoded);
			assertThat(matches).isTrue();
			assertThat(upgradeEncoding).isFalse();
		}
	}
}
