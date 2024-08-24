package com.github.justincranford.springs.util.security.hashes.encoder;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import java.util.stream.IntStream;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.password.PasswordEncoder;

import com.github.justincranford.springs.util.security.hashes.AbstractIT;
import com.github.justincranford.springs.util.security.hashes.encoder.model.KeyEncoder;
import com.github.justincranford.springs.util.security.hashes.encoder.model.KeyEncoders;
import com.github.justincranford.springs.util.security.hashes.encoder.model.ValueEncoder;
import com.github.justincranford.springs.util.security.hashes.encoder.model.ValueEncoders;

import lombok.extern.slf4j.Slf4j;

@Slf4j
@SuppressWarnings({"nls", "boxing"})
public class ConfiguredEncodersIT extends AbstractIT {
	private static final int REPEATS = 3;

	@Test
	void testTopLevelKeyEncoders() {
		helper(super.keyEncoders(), "Hello.World@example.com");
	}

	@Test
	void testEachIndividualKeyEncoder() {
		for (final KeyEncoder encoder : super.keyEncoders().idToEncoders().values()) {
			helper(encoder, "Hello.World@example.com");
		}
	}

	@Test
	void testTopLevelValueEncoders() {
		helper(super.valueEncoders(), "P@ssw0rd");
	}

	@Test
	void testEachIndividualValueEncoder() {
		for (final ValueEncoder encoder : super.valueEncoders().idToEncoders().values()) {
			helper(encoder, "P@ssw0rd");
		}
	}

	private static void helper(final PasswordEncoder encoder, final String raw) {
		// original password is encoded multiple times, each one with different (random) salt, and produces different hash
		final List<String> encodeds = IntStream.rangeClosed(1, REPEATS).boxed().map(i -> encoder.encode(raw)).toList();
		log.info("encodeds:\n{}", encodeds.stream().map(s -> "\n  "+s).toList().toString().replace("]", "\n]"));

		// original password matches all encoded hashes+parameters
		for (final String encoded : encodeds) {
			if (encoder instanceof KeyEncoders keyEncoders) {
				assertThat(encoded).startsWith("{" + keyEncoders.idForEncode() + "}");
			} else if (encoder instanceof ValueEncoders valueEncoders) {
				assertThat(encoded).startsWith("{" + valueEncoders.idForEncode() + "}");
			} else if (encoder instanceof KeyEncoder) {
				assertThat(encoded).doesNotStartWith("{");
			} else if (encoder instanceof ValueEncoder) {
				assertThat(encoded).doesNotStartWith("{");
			} else {
				throw new RuntimeException("Unexpected encoder");
			}
			final boolean matches = encoder.matches(raw, encoded);
			final boolean upgradeEncoding = encoder.upgradeEncoding(encoded);
			log.info("encoder: {}, matches: {}, upgradeEncoding: {}, raw: {}, encoded: {}", encoder.getClass().getSimpleName(), matches, upgradeEncoding, raw, encoded);
			assertThat(matches).isTrue();
			assertThat(upgradeEncoding).isFalse();
		}
	}
}
