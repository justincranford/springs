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
	private static final int REPEATS = 1;

	private static final Map<String, PasswordEncoder> keyEncodersMap = new LinkedHashMap<>() {{
		final AtomicInteger id = new AtomicInteger(0);
		List.of(
//			PepperedPbkdf2EncoderV1TestInstances.Derived.VARS_CONS_NULL_NULL_NULL,
			PepperedPbkdf2EncoderV1TestInstances.Derived.VARS_CONS_HPWDNOD_HPWDNOD_HPWDNOD,
			PepperedPbkdf2EncoderV1TestInstances.Derived.VARS_CONS_HPWDNODCTX_HPWDNODCTX_HPWDNODCTX,
			PepperedPbkdf2EncoderV1TestInstances.Derived.VARS_CONS_HKEYNOD_HKEYNOD_HKEYNOD,
			PepperedPbkdf2EncoderV1TestInstances.Derived.VARS_CONS_HKEYNODCTX_HKEYNODCTX_HKEYNODCTX,
			PepperedPbkdf2EncoderV1TestInstances.Derived.VARS_CONS_HPWDDER_HPWDDER_HPWDDER,
			PepperedPbkdf2EncoderV1TestInstances.Derived.VARS_CONS_HPWDDERCTX_HPWDDERCTX_HPWDDERCTX,
			PepperedPbkdf2EncoderV1TestInstances.Derived.VARS_CONS_HKEYDER_HKEYDER_HKEYDER,
			PepperedPbkdf2EncoderV1TestInstances.Derived.VARS_CONS_HKEYDERCTX_HKEYDERCTX_HKEYDERCTX,
			PepperedPbkdf2EncoderV1TestInstances.Derived.VARS_CONS_CPWDDER_CPWDDER_CPWDDER,
			PepperedPbkdf2EncoderV1TestInstances.Derived.VARS_CONS_CPWDDERCTX_CPWDDERCTX_CPWDDERCTX,
			PepperedPbkdf2EncoderV1TestInstances.Derived.VARS_CONS_CKEYDER_CKEYDER_CKEYDER,
			PepperedPbkdf2EncoderV1TestInstances.Derived.VARS_CONS_CKEYDERCTX_CKEYDERCTX_CKEYDERCTX,

//			PepperedPbkdf2EncoderV1TestInstances.Derived.VARS_NULL_NULL_NULL,
			PepperedPbkdf2EncoderV1TestInstances.Derived.VARS_HPWDNOD_HPWDNOD_HPWDNOD,
			PepperedPbkdf2EncoderV1TestInstances.Derived.VARS_HPWDNODCTX_HPWDNODCTX_HPWDNODCTX,
			PepperedPbkdf2EncoderV1TestInstances.Derived.VARS_HKEYNOD_HKEYNOD_HKEYNOD,
			PepperedPbkdf2EncoderV1TestInstances.Derived.VARS_HKEYNODCTX_HKEYNODCTX_HKEYNODCTX,
			PepperedPbkdf2EncoderV1TestInstances.Derived.VARS_HPWDDER_HPWDDER_HPWDDER,
			PepperedPbkdf2EncoderV1TestInstances.Derived.VARS_HPWDDERCTX_HPWDDERCTX_HPWDDERCTX,
			PepperedPbkdf2EncoderV1TestInstances.Derived.VARS_HKEYDER_HKEYDER_HKEYDER,
			PepperedPbkdf2EncoderV1TestInstances.Derived.VARS_HKEYDERCTX_HKEYDERCTX_HKEYDERCTX,
			PepperedPbkdf2EncoderV1TestInstances.Derived.VARS_CPWDDER_CPWDDER_CPWDDER,
			PepperedPbkdf2EncoderV1TestInstances.Derived.VARS_CPWDDERCTX_CPWDDERCTX_CPWDDERCTX,
			PepperedPbkdf2EncoderV1TestInstances.Derived.VARS_CKEYDER_CKEYDER_CKEYDER,
			PepperedPbkdf2EncoderV1TestInstances.Derived.VARS_CKEYDERCTX_CKEYDERCTX_CKEYDERCTX,

//			PepperedPbkdf2EncoderV1TestInstances.Derived.CONS_NULL_NULL_NULL,
			PepperedPbkdf2EncoderV1TestInstances.Derived.CONS_HPWDNOD_HPWDNOD_HPWDNOD,
			PepperedPbkdf2EncoderV1TestInstances.Derived.CONS_HPWDNODCTX_HPWDNODCTX_HPWDNODCTX,
			PepperedPbkdf2EncoderV1TestInstances.Derived.CONS_HKEYNOD_HKEYNOD_HKEYNOD,
			PepperedPbkdf2EncoderV1TestInstances.Derived.CONS_HKEYNODCTX_HKEYNODCTX_HKEYNODCTX,
			PepperedPbkdf2EncoderV1TestInstances.Derived.CONS_HPWDDER_HPWDDER_HPWDDER,
			PepperedPbkdf2EncoderV1TestInstances.Derived.CONS_HPWDDERCTX_HPWDDERCTX_HPWDDERCTX,
			PepperedPbkdf2EncoderV1TestInstances.Derived.CONS_HKEYDER_HKEYDER_HKEYDER,
			PepperedPbkdf2EncoderV1TestInstances.Derived.CONS_HKEYDERCTX_HKEYDERCTX_HKEYDERCTX,
			PepperedPbkdf2EncoderV1TestInstances.Derived.CONS_CPWDDER_CPWDDER_CPWDDER,
			PepperedPbkdf2EncoderV1TestInstances.Derived.CONS_CPWDDERCTX_CPWDDERCTX_CPWDDERCTX,
			PepperedPbkdf2EncoderV1TestInstances.Derived.CONS_CKEYDER_CKEYDER_CKEYDER,
			PepperedPbkdf2EncoderV1TestInstances.Derived.CONS_CKEYDERCTX_CKEYDERCTX_CKEYDERCTX,

//			PepperedPbkdf2EncoderV1TestInstances.Derived.NONE_NULL_NULL_NULL,
			PepperedPbkdf2EncoderV1TestInstances.Derived.NONE_HPWDNOD_HPWDNOD_HPWDNOD,
			PepperedPbkdf2EncoderV1TestInstances.Derived.NONE_HPWDNODCTX_HPWDNODCTX_HPWDNODCTX,
			PepperedPbkdf2EncoderV1TestInstances.Derived.NONE_HKEYNOD_HKEYNOD_HKEYNOD,
			PepperedPbkdf2EncoderV1TestInstances.Derived.NONE_HKEYNODCTX_HKEYNODCTX_HKEYNODCTX,
			PepperedPbkdf2EncoderV1TestInstances.Derived.NONE_HPWDDER_HPWDDER_HPWDDER,
			PepperedPbkdf2EncoderV1TestInstances.Derived.NONE_HPWDDERCTX_HPWDDERCTX_HPWDDERCTX,
			PepperedPbkdf2EncoderV1TestInstances.Derived.NONE_HKEYDER_HKEYDER_HKEYDER,
			PepperedPbkdf2EncoderV1TestInstances.Derived.NONE_HKEYDERCTX_HKEYDERCTX_HKEYDERCTX,
			PepperedPbkdf2EncoderV1TestInstances.Derived.NONE_CPWDDER_CPWDDER_CPWDDER,
			PepperedPbkdf2EncoderV1TestInstances.Derived.NONE_CPWDDERCTX_CPWDDERCTX_CPWDDERCTX,
			PepperedPbkdf2EncoderV1TestInstances.Derived.NONE_CKEYDER_CKEYDER_CKEYDER,
			PepperedPbkdf2EncoderV1TestInstances.Derived.NONE_CKEYDERCTX_CKEYDERCTX_CKEYDERCTX,

			PepperedPbkdf2EncoderV1TestInstances.Constant.VARS_CONS_NULL_NULL_NULL,
			PepperedPbkdf2EncoderV1TestInstances.Constant.VARS_CONS_HPWDNOD_HPWDNOD_HPWDNOD,
			PepperedPbkdf2EncoderV1TestInstances.Constant.VARS_CONS_HPWDNODCTX_HPWDNODCTX_HPWDNODCTX,
			PepperedPbkdf2EncoderV1TestInstances.Constant.VARS_CONS_HKEYNOD_HKEYNOD_HKEYNOD,
			PepperedPbkdf2EncoderV1TestInstances.Constant.VARS_CONS_HKEYNODCTX_HKEYNODCTX_HKEYNODCTX,
			PepperedPbkdf2EncoderV1TestInstances.Constant.VARS_CONS_HPWDDER_HPWDDER_HPWDDER,
			PepperedPbkdf2EncoderV1TestInstances.Constant.VARS_CONS_HPWDDERCTX_HPWDDERCTX_HPWDDERCTX,
			PepperedPbkdf2EncoderV1TestInstances.Constant.VARS_CONS_HKEYDER_HKEYDER_HKEYDER,
			PepperedPbkdf2EncoderV1TestInstances.Constant.VARS_CONS_HKEYDERCTX_HKEYDERCTX_HKEYDERCTX,
			PepperedPbkdf2EncoderV1TestInstances.Constant.VARS_CONS_CPWDDER_CPWDDER_CPWDDER,
			PepperedPbkdf2EncoderV1TestInstances.Constant.VARS_CONS_CPWDDERCTX_CPWDDERCTX_CPWDDERCTX,
			PepperedPbkdf2EncoderV1TestInstances.Constant.VARS_CONS_CKEYDER_CKEYDER_CKEYDER,
			PepperedPbkdf2EncoderV1TestInstances.Constant.VARS_CONS_CKEYDERCTX_CKEYDERCTX_CKEYDERCTX,

			PepperedPbkdf2EncoderV1TestInstances.Constant.VARS_NULL_NULL_NULL,
			PepperedPbkdf2EncoderV1TestInstances.Constant.VARS_HPWDNOD_HPWDNOD_HPWDNOD,
			PepperedPbkdf2EncoderV1TestInstances.Constant.VARS_HPWDNODCTX_HPWDNODCTX_HPWDNODCTX,
			PepperedPbkdf2EncoderV1TestInstances.Constant.VARS_HKEYNOD_HKEYNOD_HKEYNOD,
			PepperedPbkdf2EncoderV1TestInstances.Constant.VARS_HKEYNODCTX_HKEYNODCTX_HKEYNODCTX,
			PepperedPbkdf2EncoderV1TestInstances.Constant.VARS_HPWDDER_HPWDDER_HPWDDER,
			PepperedPbkdf2EncoderV1TestInstances.Constant.VARS_HPWDDERCTX_HPWDDERCTX_HPWDDERCTX,
			PepperedPbkdf2EncoderV1TestInstances.Constant.VARS_HKEYDER_HKEYDER_HKEYDER,
			PepperedPbkdf2EncoderV1TestInstances.Constant.VARS_HKEYDERCTX_HKEYDERCTX_HKEYDERCTX,
			PepperedPbkdf2EncoderV1TestInstances.Constant.VARS_CPWDDER_CPWDDER_CPWDDER,
			PepperedPbkdf2EncoderV1TestInstances.Constant.VARS_CPWDDERCTX_CPWDDERCTX_CPWDDERCTX,
			PepperedPbkdf2EncoderV1TestInstances.Constant.VARS_CKEYDER_CKEYDER_CKEYDER,
			PepperedPbkdf2EncoderV1TestInstances.Constant.VARS_CKEYDERCTX_CKEYDERCTX_CKEYDERCTX,

			PepperedPbkdf2EncoderV1TestInstances.Constant.CONS_NULL_NULL_NULL,
			PepperedPbkdf2EncoderV1TestInstances.Constant.CONS_HPWDNOD_HPWDNOD_HPWDNOD,
			PepperedPbkdf2EncoderV1TestInstances.Constant.CONS_HPWDNODCTX_HPWDNODCTX_HPWDNODCTX,
			PepperedPbkdf2EncoderV1TestInstances.Constant.CONS_HKEYNOD_HKEYNOD_HKEYNOD,
			PepperedPbkdf2EncoderV1TestInstances.Constant.CONS_HKEYNODCTX_HKEYNODCTX_HKEYNODCTX,
			PepperedPbkdf2EncoderV1TestInstances.Constant.CONS_HPWDDER_HPWDDER_HPWDDER,
			PepperedPbkdf2EncoderV1TestInstances.Constant.CONS_HPWDDERCTX_HPWDDERCTX_HPWDDERCTX,
			PepperedPbkdf2EncoderV1TestInstances.Constant.CONS_HKEYDER_HKEYDER_HKEYDER,
			PepperedPbkdf2EncoderV1TestInstances.Constant.CONS_HKEYDERCTX_HKEYDERCTX_HKEYDERCTX,
			PepperedPbkdf2EncoderV1TestInstances.Constant.CONS_CPWDDER_CPWDDER_CPWDDER,
			PepperedPbkdf2EncoderV1TestInstances.Constant.CONS_CPWDDERCTX_CPWDDERCTX_CPWDDERCTX,
			PepperedPbkdf2EncoderV1TestInstances.Constant.CONS_CKEYDER_CKEYDER_CKEYDER,
			PepperedPbkdf2EncoderV1TestInstances.Constant.CONS_CKEYDERCTX_CKEYDERCTX_CKEYDERCTX,

			PepperedPbkdf2EncoderV1TestInstances.Constant.NONE_NULL_NULL_NULL,
			PepperedPbkdf2EncoderV1TestInstances.Constant.NONE_HPWDNOD_HPWDNOD_HPWDNOD,
			PepperedPbkdf2EncoderV1TestInstances.Constant.NONE_HPWDNODCTX_HPWDNODCTX_HPWDNODCTX,
			PepperedPbkdf2EncoderV1TestInstances.Constant.NONE_HKEYNOD_HKEYNOD_HKEYNOD,
			PepperedPbkdf2EncoderV1TestInstances.Constant.NONE_HKEYNODCTX_HKEYNODCTX_HKEYNODCTX,
			PepperedPbkdf2EncoderV1TestInstances.Constant.NONE_HPWDDER_HPWDDER_HPWDDER,
			PepperedPbkdf2EncoderV1TestInstances.Constant.NONE_HPWDDERCTX_HPWDDERCTX_HPWDDERCTX,
			PepperedPbkdf2EncoderV1TestInstances.Constant.NONE_HKEYDER_HKEYDER_HKEYDER,
			PepperedPbkdf2EncoderV1TestInstances.Constant.NONE_HKEYDERCTX_HKEYDERCTX_HKEYDERCTX,
			PepperedPbkdf2EncoderV1TestInstances.Constant.NONE_CPWDDER_CPWDDER_CPWDDER,
			PepperedPbkdf2EncoderV1TestInstances.Constant.NONE_CPWDDERCTX_CPWDDERCTX_CPWDDERCTX,
			PepperedPbkdf2EncoderV1TestInstances.Constant.NONE_CKEYDER_CKEYDER_CKEYDER,
			PepperedPbkdf2EncoderV1TestInstances.Constant.NONE_CKEYDERCTX_CKEYDERCTX_CKEYDERCTX
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
			PepperedPbkdf2EncoderV1TestInstances.Random.VARS_CONS_NULL_NULL_NULL,
			PepperedPbkdf2EncoderV1TestInstances.Random.VARS_CONS_HPWDNOD_HPWDNOD_HPWDNOD,
			PepperedPbkdf2EncoderV1TestInstances.Random.VARS_CONS_HPWDNODCTX_HPWDNODCTX_HPWDNODCTX,
			PepperedPbkdf2EncoderV1TestInstances.Random.VARS_CONS_HKEYNOD_HKEYNOD_HKEYNOD,
			PepperedPbkdf2EncoderV1TestInstances.Random.VARS_CONS_HKEYNODCTX_HKEYNODCTX_HKEYNODCTX,
			PepperedPbkdf2EncoderV1TestInstances.Random.VARS_CONS_HPWDDER_HPWDDER_HPWDDER,
			PepperedPbkdf2EncoderV1TestInstances.Random.VARS_CONS_HPWDDERCTX_HPWDDERCTX_HPWDDERCTX,
			PepperedPbkdf2EncoderV1TestInstances.Random.VARS_CONS_HKEYDER_HKEYDER_HKEYDER,
			PepperedPbkdf2EncoderV1TestInstances.Random.VARS_CONS_HKEYDERCTX_HKEYDERCTX_HKEYDERCTX,
			PepperedPbkdf2EncoderV1TestInstances.Random.VARS_CONS_CPWDDER_CPWDDER_CPWDDER,
			PepperedPbkdf2EncoderV1TestInstances.Random.VARS_CONS_CPWDDERCTX_CPWDDERCTX_CPWDDERCTX,
			PepperedPbkdf2EncoderV1TestInstances.Random.VARS_CONS_CKEYDER_CKEYDER_CKEYDER,
			PepperedPbkdf2EncoderV1TestInstances.Random.VARS_CONS_CKEYDERCTX_CKEYDERCTX_CKEYDERCTX,

			PepperedPbkdf2EncoderV1TestInstances.Random.VARS_NULL_NULL_NULL,
			PepperedPbkdf2EncoderV1TestInstances.Random.VARS_HPWDNOD_HPWDNOD_HPWDNOD,
			PepperedPbkdf2EncoderV1TestInstances.Random.VARS_HPWDNODCTX_HPWDNODCTX_HPWDNODCTX,
			PepperedPbkdf2EncoderV1TestInstances.Random.VARS_HKEYNOD_HKEYNOD_HKEYNOD,
			PepperedPbkdf2EncoderV1TestInstances.Random.VARS_HKEYNODCTX_HKEYNODCTX_HKEYNODCTX,
			PepperedPbkdf2EncoderV1TestInstances.Random.VARS_HPWDDER_HPWDDER_HPWDDER,
			PepperedPbkdf2EncoderV1TestInstances.Random.VARS_HPWDDERCTX_HPWDDERCTX_HPWDDERCTX,
			PepperedPbkdf2EncoderV1TestInstances.Random.VARS_HKEYDER_HKEYDER_HKEYDER,
			PepperedPbkdf2EncoderV1TestInstances.Random.VARS_HKEYDERCTX_HKEYDERCTX_HKEYDERCTX,
			PepperedPbkdf2EncoderV1TestInstances.Random.VARS_CPWDDER_CPWDDER_CPWDDER,
			PepperedPbkdf2EncoderV1TestInstances.Random.VARS_CPWDDERCTX_CPWDDERCTX_CPWDDERCTX,
			PepperedPbkdf2EncoderV1TestInstances.Random.VARS_CKEYDER_CKEYDER_CKEYDER,
			PepperedPbkdf2EncoderV1TestInstances.Random.VARS_CKEYDERCTX_CKEYDERCTX_CKEYDERCTX
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
//						assertThat(upgradeEncoding).isFalse();
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
