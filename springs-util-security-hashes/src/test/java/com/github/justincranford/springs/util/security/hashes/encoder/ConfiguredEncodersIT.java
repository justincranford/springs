package com.github.justincranford.springs.util.security.hashes.encoder;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import java.util.stream.IntStream;

import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.springframework.security.crypto.password.PasswordEncoder;

import com.github.justincranford.springs.util.security.hashes.AbstractIT;
import com.github.justincranford.springs.util.security.hashes.encoder.model.Encoder;
import com.github.justincranford.springs.util.security.hashes.encoder.model.Encoders;

import lombok.extern.slf4j.Slf4j;

@Slf4j
@SuppressWarnings({"nls", "boxing"})
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
public class ConfiguredEncodersIT extends AbstractIT {
	private static final int REPEATS = 3;

	@Order(1)
	@Test
	void testTopLevelKeyEncoders() {
		helper(super.keyEncoders(), "Hello.World@example.com");
	}

	@Order(2)
	@Test
	void testTopLevelValueEncoders() {
		helper(super.valueEncoders(), "P@ssw0rd");
	}

	@Order(3)
	@Test
	void testEachIndividualKeyEncoder() {
		super.keyEncoders().idToEncoders().values().forEach(keyEncoder -> helper(keyEncoder, "Hello.World@example.com"));
	}

	@Order(4)
	@Test
	void testEachIndividualValueEncoder() {
		super.valueEncoders().idToEncoders().values().forEach(valueEncoder -> helper(valueEncoder, "P@ssw0rd"));
	}

	private static void helper(final PasswordEncoder passwordEncoder, final String raw) {
		// original password is encoded multiple times, each one with different (random) salt, and produces different hash
		final List<String> encodeds = IntStream.rangeClosed(1, REPEATS).boxed().map(i -> passwordEncoder.encode(raw)).toList();
//		log.info("encodeds:\n{}", encodeds.stream().map(s -> "\n  "+s).toList().toString().replace("]", "\n]"));

		// original password matches all encoded hashes+parameters
		for (final String encoded : encodeds) {
			final String idForEncode;
			if (passwordEncoder instanceof Encoders encoders) { // KeyEncoders, ValueEncoders
				assertThat(encoded).startsWith("{" + encoders.idForEncode() + "}");
				idForEncode = encoders.idForEncode();
			} else if (passwordEncoder instanceof Encoder encoder) { // KeyEncoder, ValueEncoder
				assertThat(encoded).doesNotStartWith("{");
				idForEncode = encoder.idForEncode();
			} else {
				throw new RuntimeException("Unexpected encoder");
			}
			final boolean matches = passwordEncoder.matches(raw, encoded);
			final boolean upgradeEncoding = passwordEncoder.upgradeEncoding(encoded);
			log.info("class: {}, idForEncode: {}, matches: {}, upgradeEncoding: {}, raw: {}, encoded: {}", passwordEncoder.getClass().getSimpleName(), idForEncode, matches, upgradeEncoding, raw, encoded);
			assertThat(matches).isTrue();
			assertThat(upgradeEncoding).isFalse();
		}
	}
}
