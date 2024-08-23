package com.github.justincranford.springs.util.security.hashes.encoder;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.stream.IntStream;

import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.password.PasswordEncoder;

import com.github.justincranford.springs.util.security.hashes.AbstractIT;
import com.github.justincranford.springs.util.security.hashes.encoder.EncodersConfiguration.KeyEncoders;
import com.github.justincranford.springs.util.security.hashes.encoder.EncodersConfiguration.ValueEncoders;

import lombok.extern.slf4j.Slf4j;

@Slf4j
@SuppressWarnings({"nls", "boxing"})
public class ConfiguredEncodersIT extends AbstractIT {
	private static final int REPEATS = 3;

	@Test
	void testKeyEncoders() {
		final String rawEmailAddress = "Hello.World@example.com";
		log.info("rawEmailAddress: {}", rawEmailAddress);

		final KeyEncoders keyEncoders = super.keyEncoders();
		final String currentIdForEncode = keyEncoders.currentIdForEncode();
		final LinkedHashMap<String, PasswordEncoder> idToEncoders = keyEncoders.idToEncoders();

		// original email address is encoded multiple times, each one with same (derived) salt, and produces same hash
		final List<String> encodedEmailAddressList = IntStream.rangeClosed(1, REPEATS).boxed().map(i -> keyEncoders.encode(rawEmailAddress)).toList();
		log.info("encodedEmailAddressList:\n{}", encodedEmailAddressList.stream().map(s -> "\n  "+s).toList().toString().replace("]", "\n]"));

		// original email address matches all encoded hashes+parameters
		for (final String encodedEmailAddress : encodedEmailAddressList) {
			final boolean matches = keyEncoders.matches(rawEmailAddress, encodedEmailAddress);
			final boolean upgradeEncoding = keyEncoders.upgradeEncoding(encodedEmailAddress);
			log.info("encoder: {}, matches: {}, upgradeEncoding: {}, rawEmailAddress: {}, encodedEmailAddress: {}", keyEncoders.getClass().getSimpleName(), matches, upgradeEncoding, rawEmailAddress, encodedEmailAddress);
			assertThat(matches).isTrue();
			assertThat(upgradeEncoding).isFalse();
			assertThat(encodedEmailAddress).startsWith("{" + currentIdForEncode + "}");
		}
	}

	@Test
	void testValueEncoders() {
		final String rawPassword = "Password1234";
		log.info("rawPassword: {}", rawPassword);

		final ValueEncoders valueEncoders = super.valueEncoders();
		final String currentIdForEncode = valueEncoders.currentIdForEncode();
		final LinkedHashMap<String, PasswordEncoder> idToEncoders = valueEncoders.idToEncoders();

		// original password is encoded multiple times, each one with different (random) salt, and produces different hash
		final List<String> encodedPasswordList = IntStream.rangeClosed(1, REPEATS).boxed().map(i -> valueEncoders.encode(rawPassword)).toList();
		log.info("encodedPasswordList:\n{}", encodedPasswordList.stream().map(s -> "\n  "+s).toList().toString().replace("]", "\n]"));

		// original password matches all encoded hashes+parameters
		for (final String encodedPassword : encodedPasswordList) {
			final boolean matches = valueEncoders.matches(rawPassword, encodedPassword);
			final boolean upgradeEncoding = valueEncoders.upgradeEncoding(encodedPassword);
			log.info("encoder: {}, matches: {}, upgradeEncoding: {}, rawPassword: {}, encodedPassword: {}", valueEncoders.getClass().getSimpleName(), matches, upgradeEncoding, rawPassword, encodedPassword);
			assertThat(matches).isTrue();
			assertThat(upgradeEncoding).isFalse();
			assertThat(encodedPassword).startsWith("{" + currentIdForEncode + "}");
		}
	}
}
