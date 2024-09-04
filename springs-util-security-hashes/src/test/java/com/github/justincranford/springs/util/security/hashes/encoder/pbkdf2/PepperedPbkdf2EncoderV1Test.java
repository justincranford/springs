package com.github.justincranford.springs.util.security.hashes.encoder.pbkdf2;

import static org.assertj.core.api.Assertions.assertThat;

import java.security.Security;
import java.util.LinkedHashMap;
import java.util.List;
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
public class PepperedPbkdf2EncoderV1Test {
	private static final int REPEATS = 2;

	private static final Map<String, PasswordEncoder> keyEncodersMap = new LinkedHashMap<>() {{
		final AtomicInteger id = new AtomicInteger(0);
		List.of(
			PepperedPbkdf2EncoderV1TestInstances.Derived.SALTOTH_NULL_NULL_NULL,
			PepperedPbkdf2EncoderV1TestInstances.Derived.SALTOTH_NONE_NONE_NONE,
			PepperedPbkdf2EncoderV1TestInstances.Derived.SALTOTH_CTX_CTX_CTX,
			PepperedPbkdf2EncoderV1TestInstances.Derived.SALTOTH_SK_SK_SK,
			PepperedPbkdf2EncoderV1TestInstances.Derived.SALTOTH_SKCTX_SKCTX_SKCTX,
			PepperedPbkdf2EncoderV1TestInstances.Derived.SALT_NULL_NULL_NULL,
			PepperedPbkdf2EncoderV1TestInstances.Derived.SALT_NONE_NONE_NONE,
			PepperedPbkdf2EncoderV1TestInstances.Derived.SALT_CTX_CTX_CTX,
			PepperedPbkdf2EncoderV1TestInstances.Derived.SALT_SK_SK_SK,
			PepperedPbkdf2EncoderV1TestInstances.Derived.SALT_SKCTX_SKCTX_SKCTX,
			PepperedPbkdf2EncoderV1TestInstances.Derived.OTH_NULL_NULL_NULL,
			PepperedPbkdf2EncoderV1TestInstances.Derived.OTH_NONE_NONE_NONE,
			PepperedPbkdf2EncoderV1TestInstances.Derived.OTH_CTX_CTX_CTX,
			PepperedPbkdf2EncoderV1TestInstances.Derived.OTH_SK_SK_SK,
			PepperedPbkdf2EncoderV1TestInstances.Derived.OTH_SKCTX_SKCTX_SKCTX,
			PepperedPbkdf2EncoderV1TestInstances.Derived.NONE_NULL_NULL_NULL,
			PepperedPbkdf2EncoderV1TestInstances.Derived.NONE_NONE_NONE_NONE,
			PepperedPbkdf2EncoderV1TestInstances.Derived.NONE_CTX_CTX_CTX,
			PepperedPbkdf2EncoderV1TestInstances.Derived.NONE_SK_SK_SK,
			PepperedPbkdf2EncoderV1TestInstances.Derived.NONE_SKCTX_SKCTX_SKCTX,

			PepperedPbkdf2EncoderV1TestInstances.Constant.SALTOTH_NULL_NULL_NULL,
			PepperedPbkdf2EncoderV1TestInstances.Constant.SALTOTH_NONE_NONE_NONE,
			PepperedPbkdf2EncoderV1TestInstances.Constant.SALTOTH_CTX_CTX_CTX,
			PepperedPbkdf2EncoderV1TestInstances.Constant.SALTOTH_SK_SK_SK,
			PepperedPbkdf2EncoderV1TestInstances.Constant.SALTOTH_SKCTX_SKCTX_SKCTX,
			PepperedPbkdf2EncoderV1TestInstances.Constant.SALT_NULL_NULL_NULL,
			PepperedPbkdf2EncoderV1TestInstances.Constant.SALT_NONE_NONE_NONE,
			PepperedPbkdf2EncoderV1TestInstances.Constant.SALT_CTX_CTX_CTX,
			PepperedPbkdf2EncoderV1TestInstances.Constant.SALT_SK_SK_SK,
			PepperedPbkdf2EncoderV1TestInstances.Constant.SALT_SKCTX_SKCTX_SKCTX,
			PepperedPbkdf2EncoderV1TestInstances.Constant.OTH_NULL_NULL_NULL,
			PepperedPbkdf2EncoderV1TestInstances.Constant.OTH_NONE_NONE_NONE,
			PepperedPbkdf2EncoderV1TestInstances.Constant.OTH_CTX_CTX_CTX,
			PepperedPbkdf2EncoderV1TestInstances.Constant.OTH_SK_SK_SK,
			PepperedPbkdf2EncoderV1TestInstances.Constant.OTH_SKCTX_SKCTX_SKCTX,
			PepperedPbkdf2EncoderV1TestInstances.Constant.NONE_NULL_NULL_NULL,
			PepperedPbkdf2EncoderV1TestInstances.Constant.NONE_NONE_NONE_NONE,
			PepperedPbkdf2EncoderV1TestInstances.Constant.NONE_CTX_CTX_CTX,
			PepperedPbkdf2EncoderV1TestInstances.Constant.NONE_SK_SK_SK,
			PepperedPbkdf2EncoderV1TestInstances.Constant.NONE_SKCTX_SKCTX_SKCTX
		).forEach(valueEncoder -> put("k" + id.incrementAndGet(), valueEncoder));
	}};
	private static final String keyEncodersDefault = keyEncodersMap.keySet().iterator().next();
	private static final DelegatingPasswordEncoder keyEncoders = new DelegatingPasswordEncoder(
			keyEncodersMap.keySet().iterator().next(),
		keyEncodersMap
	);

	private static final Map<String, PasswordEncoder> valueEncodersMap = new LinkedHashMap<>() {{
		final AtomicInteger id = new AtomicInteger(0);
		List.of(
			PepperedPbkdf2EncoderV1TestInstances.Random.SALTOTH_NULL_NULL_NULL,
			PepperedPbkdf2EncoderV1TestInstances.Random.SALTOTH_NONE_NONE_NONE,
			PepperedPbkdf2EncoderV1TestInstances.Random.SALTOTH_CTX_CTX_CTX,
			PepperedPbkdf2EncoderV1TestInstances.Random.SALTOTH_SK_SK_SK,
			PepperedPbkdf2EncoderV1TestInstances.Random.SALTOTH_SKCTX_SKCTX_SKCTX,
			PepperedPbkdf2EncoderV1TestInstances.Random.SALT_NULL_NULL_NULL,
			PepperedPbkdf2EncoderV1TestInstances.Random.SALT_NONE_NONE_NONE,
			PepperedPbkdf2EncoderV1TestInstances.Random.SALT_CTX_CTX_CTX,
			PepperedPbkdf2EncoderV1TestInstances.Random.SALT_SK_SK_SK,
			PepperedPbkdf2EncoderV1TestInstances.Random.SALT_SKCTX_SKCTX_SKCTX
		).forEach(valueEncoder -> put("v" + id.incrementAndGet(), valueEncoder));
	}};
	private static final String valueEncodersDefault = valueEncodersMap.keySet().iterator().next();
	private static final DelegatingPasswordEncoder valueEncoders = new DelegatingPasswordEncoder(
		valueEncodersMap.keySet().iterator().next(),
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
		keyEncodersMap.entrySet().forEach(entry -> helper(entry.getValue(), entry.getKey(),  "Hello.World@example.com"));
	}

	@Order(4)
	@Test
	void testEachIndividualValueEncoder() {
		valueEncodersMap.entrySet().forEach(entry -> helper(entry.getValue(), entry.getKey(), "P@ssw0rd"));
	}

	private static final AtomicInteger counter = new AtomicInteger(0);
	private static void helper(final PasswordEncoder passwordEncoder, final String idForEncode, final String raw) {
		final String className = passwordEncoder.getClass().getSimpleName();
		final AtomicInteger numFailures = new AtomicInteger(0);
		try (ForkJoinPool threadPool = ThreadUtil.threadPool(REPEATS, "Thread-")) {
			IntStream.rangeClosed(1, REPEATS).forEach((i) -> {
				threadPool.submit(() -> {
					try {
						final String encoded = passwordEncoder.encode(raw);
						if (passwordEncoder instanceof DelegatingPasswordEncoder) {
							assertThat(encoded).startsWith("{" + idForEncode + "}");
						} else {
							assertThat(encoded).doesNotStartWith("{");
						}
						final boolean matches = passwordEncoder.matches(raw, encoded);
						final boolean upgradeEncoding = passwordEncoder.upgradeEncoding(encoded);
						log.info("counter: {}, class: {}, idForEncode: {}, matches: {}, upgradeEncoding: {}, raw: {}, encoded: {}", counter.incrementAndGet(), className, idForEncode, matches, upgradeEncoding, raw, encoded);
						assertThat(matches).isTrue();
						assertThat(upgradeEncoding).isFalse();
					} catch(Throwable t) {
						log.info("class: {}, idForEncode: {}, raw: {}", className, idForEncode, raw, t);
						numFailures.incrementAndGet();
					}
				});
			});
		}
		assertThat(numFailures.get()).isEqualTo(0);
	}
}
