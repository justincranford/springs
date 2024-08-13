package com.github.justincranford.springs.util.security.encoder;
import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import java.util.stream.IntStream;

import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import lombok.extern.slf4j.Slf4j;

@Slf4j
@SuppressWarnings({"nls", "static-method", "boxing"})
public class BcryptPasswordEncoderTest {
	private static final int REPEATS = 3;

	@Test
	void testBcrypt() {
		final String rawPassword = "Hello World";
		log.info("rawPassword: {}", rawPassword);

		final PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
		final List<String> encodedPasswordList = IntStream.rangeClosed(1, REPEATS).boxed().map(i -> passwordEncoder.encode(rawPassword)).toList();
		log.info("encodedPasswordList:\n{}", encodedPasswordList.stream().map(s -> "\n  "+s).toList().toString().replace("]", "\n]"));

		for (final String encodedPassword : encodedPasswordList) {
			final boolean matches = passwordEncoder.matches(rawPassword, encodedPassword);
			log.info("matches: {}, rawPassword: {}, encodedPassword: {}", matches, rawPassword, encodedPassword);
			assertThat(matches).isTrue();
		}
	}
}
