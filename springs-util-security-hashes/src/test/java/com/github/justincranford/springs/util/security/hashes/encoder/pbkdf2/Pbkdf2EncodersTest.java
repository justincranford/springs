package com.github.justincranford.springs.util.security.hashes.encoder.pbkdf2;

import static org.assertj.core.api.Assertions.assertThat;

import java.security.Security;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.ForkJoinPool;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.IntStream;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.springframework.security.crypto.password.DelegatingPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import com.github.justincranford.springs.util.basic.ThreadUtil;

import lombok.extern.slf4j.Slf4j;

@Slf4j
@SuppressWarnings({"nls", "boxing", "static-method", "serial"})
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
public class Pbkdf2EncodersTest {
	private static final int REPEATS = 3;

	private static final String keyEncodersDefault = "DEFAULT_MIN_ENCODED_KEYLESS_EMPTY_CONTEXT";
	private static final Map<String, PasswordEncoder> keyEncodersMap = new LinkedHashMap<>() {{
		put("DEFAULT_MIN_ENCODED_KEYLESS_EMPTY_CONTEXT",     Pbkdf2EncoderV1.DerivedSalt.DEFAULT_MIN_ENCODED_KEYLESS_EMPTY_CONTEXT);
		put("DEFAULT_MAX_ENCODED_KEYLESS_EMPTY_CONTEXT",     Pbkdf2EncoderV1.DerivedSalt.DEFAULT_MAX_ENCODED_KEYLESS_EMPTY_CONTEXT);
		put("DEFAULT_MIN_ENCODED_KEYLESS_EMPTY_CONTEXT",     Pbkdf2EncoderV1.ConstantSalt.DEFAULT_MIN_ENCODED_KEYLESS_EMPTY_CONTEXT);
		put("DEFAULT_MAX_ENCODED_KEYLESS_EMPTY_CONTEXT",     Pbkdf2EncoderV1.ConstantSalt.DEFAULT_MAX_ENCODED_KEYLESS_EMPTY_CONTEXT);
		put("DEFAULT_MIN_ENCODED_KEYLESS_NON_EMPTY_CONTEXT", Pbkdf2EncoderV1.DerivedSalt.DEFAULT_MIN_ENCODED_KEYLESS_NON_EMPTY_CONTEXT);
		put("DEFAULT_MAX_ENCODED_KEYLESS_NON_EMPTY_CONTEXT", Pbkdf2EncoderV1.DerivedSalt.DEFAULT_MAX_ENCODED_KEYLESS_NON_EMPTY_CONTEXT);
		put("DEFAULT_MIN_ENCODED_KEYLESS_NON_EMPTY_CONTEXT", Pbkdf2EncoderV1.ConstantSalt.DEFAULT_MIN_ENCODED_KEYLESS_NON_EMPTY_CONTEXT);
		put("DEFAULT_MAX_ENCODED_KEYLESS_NON_EMPTY_CONTEXT", Pbkdf2EncoderV1.ConstantSalt.DEFAULT_MAX_ENCODED_KEYLESS_NON_EMPTY_CONTEXT);
		put("DEFAULT_MIN_ENCODED_KEYED_EMPTY_CONTEXT",       Pbkdf2EncoderV1.DerivedSalt.DEFAULT_MIN_ENCODED_KEYED_EMPTY_CONTEXT);
		put("DEFAULT_MAX_ENCODED_KEYED_EMPTY_CONTEXT",       Pbkdf2EncoderV1.DerivedSalt.DEFAULT_MAX_ENCODED_KEYED_EMPTY_CONTEXT);
		put("DEFAULT_MIN_ENCODED_KEYED_EMPTY_CONTEXT",       Pbkdf2EncoderV1.ConstantSalt.DEFAULT_MIN_ENCODED_KEYED_EMPTY_CONTEXT);
		put("DEFAULT_MAX_ENCODED_KEYED_EMPTY_CONTEXT",       Pbkdf2EncoderV1.ConstantSalt.DEFAULT_MAX_ENCODED_KEYED_EMPTY_CONTEXT);
		put("DEFAULT_MIN_ENCODED_KEYED_NON_EMPTY_CONTEXT",   Pbkdf2EncoderV1.DerivedSalt.DEFAULT_MIN_ENCODED_KEYED_NON_EMPTY_CONTEXT);
		put("DEFAULT_MAX_ENCODED_KEYED_NON_EMPTY_CONTEXT",   Pbkdf2EncoderV1.DerivedSalt.DEFAULT_MAX_ENCODED_KEYED_NON_EMPTY_CONTEXT);
		put("DEFAULT_MIN_ENCODED_KEYED_NON_EMPTY_CONTEXT",   Pbkdf2EncoderV1.ConstantSalt.DEFAULT_MIN_ENCODED_KEYED_NON_EMPTY_CONTEXT);
		put("DEFAULT_MAX_ENCODED_KEYED_NON_EMPTY_CONTEXT",   Pbkdf2EncoderV1.ConstantSalt.DEFAULT_MAX_ENCODED_KEYED_NON_EMPTY_CONTEXT);
	}};
	private static final DelegatingPasswordEncoder keyEncoders = new DelegatingPasswordEncoder(
		keyEncodersDefault,
		keyEncodersMap
	);

	private static final String valueEncodersDefault = "DEFAULT_MIN_ENCODED_KEYLESS_EMPTY_CONTEXT";
	private static final Map<String, PasswordEncoder> valueEncodersMap = new LinkedHashMap<>() {{
		put("DEFAULT_MIN_ENCODED_KEYLESS_EMPTY_CONTEXT", Pbkdf2EncoderV1.RandomSalt.DEFAULT_MIN_ENCODED_KEYLESS_EMPTY_CONTEXT);
		put("DEFAULT_MAX_ENCODED_KEYLESS_EMPTY_CONTEXT", Pbkdf2EncoderV1.RandomSalt.DEFAULT_MAX_ENCODED_KEYLESS_EMPTY_CONTEXT);
		put("DEFAULT_MIN_ENCODED_KEYLESS_NON_EMPTY_CONTEXT", Pbkdf2EncoderV1.RandomSalt.DEFAULT_MIN_ENCODED_KEYLESS_NON_EMPTY_CONTEXT);
		put("DEFAULT_MAX_ENCODED_KEYLESS_NON_EMPTY_CONTEXT", Pbkdf2EncoderV1.RandomSalt.DEFAULT_MAX_ENCODED_KEYLESS_NON_EMPTY_CONTEXT);
	}};
	private static final DelegatingPasswordEncoder valueEncoders = new DelegatingPasswordEncoder(
		valueEncodersDefault,
		valueEncodersMap
	);

	@BeforeAll
	public static void beforeAll() {
		Security.addProvider(new BouncyCastleProvider());
	}

	@AfterAll
	public static void afterAll() {
		Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME);
	}

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
		final String className = passwordEncoder.getClass().getSimpleName();
		final AtomicInteger numFailures = new AtomicInteger(0);
		try (ForkJoinPool threadPool = ThreadUtil.threadPool(REPEATS, "Thread-")) {
			threadPool.submit(
				() -> IntStream.rangeClosed(1, REPEATS).parallel().forEach((i) -> {
					try {
						final String encoded = passwordEncoder.encode(raw);
						if (passwordEncoder instanceof DelegatingPasswordEncoder) {
							assertThat(encoded).startsWith("{" + idForEncode + "}");
						} else {
							assertThat(encoded).doesNotStartWith("{");
						}
						final boolean matches = passwordEncoder.matches(raw, encoded);
						final boolean upgradeEncoding = passwordEncoder.upgradeEncoding(encoded);
						log.info("class: {}, idForEncode: {}, matches: {}, upgradeEncoding: {}, raw: {}, encoded: {}", className, idForEncode, matches, upgradeEncoding, raw, encoded);
						assertThat(matches).isTrue();
						assertThat(upgradeEncoding).isFalse();
					} catch(Throwable t) {
						log.info("class: {}, idForEncode: {}, raw: {}", className, idForEncode, raw, t);
						numFailures.incrementAndGet();
					}
				})
			);
		}
		assertThat(numFailures.get()).isEqualTo(0);
	}
}
