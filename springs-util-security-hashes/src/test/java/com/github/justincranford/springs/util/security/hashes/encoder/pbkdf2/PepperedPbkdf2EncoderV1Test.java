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
			PepperedPbkdf2EncoderV1TestInstances.Derived.VARS_CONS_NONE_NONE_NONE,
			PepperedPbkdf2EncoderV1TestInstances.Derived.VARS_CONS_CTX_CTX_CTX,
			PepperedPbkdf2EncoderV1TestInstances.Derived.VARS_CONS_HPWD_HPWD_HPWD,
			PepperedPbkdf2EncoderV1TestInstances.Derived.VARS_CONS_HPWDCTX_HPWDCTX_HPWDCTX,
			PepperedPbkdf2EncoderV1TestInstances.Derived.VARS_CONS_HKEY_HKEY_HKEY,
			PepperedPbkdf2EncoderV1TestInstances.Derived.VARS_CONS_HKEYCTX_HKEYCTX_HKEYCTX,
			PepperedPbkdf2EncoderV1TestInstances.Derived.VARS_CONS_CPWD_CPWD_CPWD,
			PepperedPbkdf2EncoderV1TestInstances.Derived.VARS_CONS_CPWDCTX_CPWDCTX_CPWDCTX,
			PepperedPbkdf2EncoderV1TestInstances.Derived.VARS_CONS_CKEY_CKEY_CKEY,
			PepperedPbkdf2EncoderV1TestInstances.Derived.VARS_CONS_CKEYCTX_CKEYCTX_CKEYCTX,

//			PepperedPbkdf2EncoderV1TestInstances.Derived.VARS_NULL_NULL_NULL,
			PepperedPbkdf2EncoderV1TestInstances.Derived.VARS_NONE_NONE_NONE,
			PepperedPbkdf2EncoderV1TestInstances.Derived.VARS_CTX_CTX_CTX,
			PepperedPbkdf2EncoderV1TestInstances.Derived.VARS_HPWD_HPWD_HPWD,
			PepperedPbkdf2EncoderV1TestInstances.Derived.VARS_HPWDCTX_HPWDCTX_HPWDCTX,
			PepperedPbkdf2EncoderV1TestInstances.Derived.VARS_HKEY_HKEY_HKEY,
			PepperedPbkdf2EncoderV1TestInstances.Derived.VARS_HKEYCTX_HKEYCTX_HKEYCTX,
			PepperedPbkdf2EncoderV1TestInstances.Derived.VARS_CPWD_CPWD_CPWD,
			PepperedPbkdf2EncoderV1TestInstances.Derived.VARS_CPWDCTX_CPWDCTX_CPWDCTX,
			PepperedPbkdf2EncoderV1TestInstances.Derived.VARS_CKEY_CKEY_CKEY,
			PepperedPbkdf2EncoderV1TestInstances.Derived.VARS_CKEYCTX_CKEYCTX_CKEYCTX,

//			PepperedPbkdf2EncoderV1TestInstances.Derived.CONS_NULL_NULL_NULL,
			PepperedPbkdf2EncoderV1TestInstances.Derived.CONS_NONE_NONE_NONE,
			PepperedPbkdf2EncoderV1TestInstances.Derived.CONS_CTX_CTX_CTX,
			PepperedPbkdf2EncoderV1TestInstances.Derived.CONS_HPWD_HPWD_HPWD,
			PepperedPbkdf2EncoderV1TestInstances.Derived.CONS_HPWDCTX_HPWDCTX_HPWDCTX,
			PepperedPbkdf2EncoderV1TestInstances.Derived.CONS_HKEY_HKEY_HKEY,
			PepperedPbkdf2EncoderV1TestInstances.Derived.CONS_HKEYCTX_HKEYCTX_HKEYCTX,
			PepperedPbkdf2EncoderV1TestInstances.Derived.CONS_CPWD_CPWD_CPWD,
			PepperedPbkdf2EncoderV1TestInstances.Derived.CONS_CPWDCTX_CPWDCTX_CPWDCTX,
			PepperedPbkdf2EncoderV1TestInstances.Derived.CONS_CKEY_CKEY_CKEY,
			PepperedPbkdf2EncoderV1TestInstances.Derived.CONS_CKEYCTX_CKEYCTX_CKEYCTX,

//			PepperedPbkdf2EncoderV1TestInstances.Derived.NONE_NULL_NULL_NULL,
			PepperedPbkdf2EncoderV1TestInstances.Derived.NONE_NONE_NONE_NONE,
			PepperedPbkdf2EncoderV1TestInstances.Derived.NONE_CTX_CTX_CTX,
			PepperedPbkdf2EncoderV1TestInstances.Derived.NONE_HPWD_HPWD_HPWD,
			PepperedPbkdf2EncoderV1TestInstances.Derived.NONE_HPWDCTX_HPWDCTX_HPWDCTX,
			PepperedPbkdf2EncoderV1TestInstances.Derived.NONE_HKEY_HKEY_HKEY,
			PepperedPbkdf2EncoderV1TestInstances.Derived.NONE_HKEYCTX_HKEYCTX_HKEYCTX,
			PepperedPbkdf2EncoderV1TestInstances.Derived.NONE_CPWD_CPWD_CPWD,
			PepperedPbkdf2EncoderV1TestInstances.Derived.NONE_CPWDCTX_CPWDCTX_CPWDCTX,
			PepperedPbkdf2EncoderV1TestInstances.Derived.NONE_CKEY_CKEY_CKEY,
			PepperedPbkdf2EncoderV1TestInstances.Derived.NONE_CKEYCTX_CKEYCTX_CKEYCTX,

			PepperedPbkdf2EncoderV1TestInstances.Constant.VARS_CONS_NULL_NULL_NULL,
			PepperedPbkdf2EncoderV1TestInstances.Constant.VARS_CONS_NONE_NONE_NONE,
			PepperedPbkdf2EncoderV1TestInstances.Constant.VARS_CONS_CTX_CTX_CTX,
			PepperedPbkdf2EncoderV1TestInstances.Constant.VARS_CONS_HPWD_HPWD_HPWD,
			PepperedPbkdf2EncoderV1TestInstances.Constant.VARS_CONS_HPWDCTX_HPWDCTX_HPWDCTX,
			PepperedPbkdf2EncoderV1TestInstances.Constant.VARS_CONS_HKEY_HKEY_HKEY,
			PepperedPbkdf2EncoderV1TestInstances.Constant.VARS_CONS_HKEYCTX_HKEYCTX_HKEYCTX,
			PepperedPbkdf2EncoderV1TestInstances.Constant.VARS_CONS_CPWD_CPWD_CPWD,
			PepperedPbkdf2EncoderV1TestInstances.Constant.VARS_CONS_CPWDCTX_CPWDCTX_CPWDCTX,
			PepperedPbkdf2EncoderV1TestInstances.Constant.VARS_CONS_CKEY_CKEY_CKEY,
			PepperedPbkdf2EncoderV1TestInstances.Constant.VARS_CONS_CKEYCTX_CKEYCTX_CKEYCTX,

			PepperedPbkdf2EncoderV1TestInstances.Constant.VARS_NULL_NULL_NULL,
			PepperedPbkdf2EncoderV1TestInstances.Constant.VARS_NONE_NONE_NONE,
			PepperedPbkdf2EncoderV1TestInstances.Constant.VARS_CTX_CTX_CTX,
			PepperedPbkdf2EncoderV1TestInstances.Constant.VARS_HPWD_HPWD_HPWD,
			PepperedPbkdf2EncoderV1TestInstances.Constant.VARS_HPWDCTX_HPWDCTX_HPWDCTX,
			PepperedPbkdf2EncoderV1TestInstances.Constant.VARS_HKEY_HKEY_HKEY,
			PepperedPbkdf2EncoderV1TestInstances.Constant.VARS_HKEYCTX_HKEYCTX_HKEYCTX,
			PepperedPbkdf2EncoderV1TestInstances.Constant.VARS_CPWD_CPWD_CPWD,
			PepperedPbkdf2EncoderV1TestInstances.Constant.VARS_CPWDCTX_CPWDCTX_CPWDCTX,
			PepperedPbkdf2EncoderV1TestInstances.Constant.VARS_CKEY_CKEY_CKEY,
			PepperedPbkdf2EncoderV1TestInstances.Constant.VARS_CKEYCTX_CKEYCTX_CKEYCTX,

			PepperedPbkdf2EncoderV1TestInstances.Constant.CONS_NULL_NULL_NULL,
			PepperedPbkdf2EncoderV1TestInstances.Constant.CONS_NONE_NONE_NONE,
			PepperedPbkdf2EncoderV1TestInstances.Constant.CONS_CTX_CTX_CTX,
			PepperedPbkdf2EncoderV1TestInstances.Constant.CONS_HPWD_HPWD_HPWD,
			PepperedPbkdf2EncoderV1TestInstances.Constant.CONS_HPWDCTX_HPWDCTX_HPWDCTX,
			PepperedPbkdf2EncoderV1TestInstances.Constant.CONS_HKEY_HKEY_HKEY,
			PepperedPbkdf2EncoderV1TestInstances.Constant.CONS_HKEYCTX_HKEYCTX_HKEYCTX,
			PepperedPbkdf2EncoderV1TestInstances.Constant.CONS_CPWD_CPWD_CPWD,
			PepperedPbkdf2EncoderV1TestInstances.Constant.CONS_CPWDCTX_CPWDCTX_CPWDCTX,
			PepperedPbkdf2EncoderV1TestInstances.Constant.CONS_CKEY_CKEY_CKEY,
			PepperedPbkdf2EncoderV1TestInstances.Constant.CONS_CKEYCTX_CKEYCTX_CKEYCTX,

			PepperedPbkdf2EncoderV1TestInstances.Constant.NONE_NULL_NULL_NULL,
			PepperedPbkdf2EncoderV1TestInstances.Constant.NONE_NONE_NONE_NONE,
			PepperedPbkdf2EncoderV1TestInstances.Constant.NONE_CTX_CTX_CTX,
			PepperedPbkdf2EncoderV1TestInstances.Constant.NONE_HPWD_HPWD_HPWD,
			PepperedPbkdf2EncoderV1TestInstances.Constant.NONE_HPWDCTX_HPWDCTX_HPWDCTX,
			PepperedPbkdf2EncoderV1TestInstances.Constant.NONE_HKEY_HKEY_HKEY,
			PepperedPbkdf2EncoderV1TestInstances.Constant.NONE_HKEYCTX_HKEYCTX_HKEYCTX,
			PepperedPbkdf2EncoderV1TestInstances.Constant.NONE_CPWD_CPWD_CPWD,
			PepperedPbkdf2EncoderV1TestInstances.Constant.NONE_CPWDCTX_CPWDCTX_CPWDCTX,
			PepperedPbkdf2EncoderV1TestInstances.Constant.NONE_CKEY_CKEY_CKEY,
			PepperedPbkdf2EncoderV1TestInstances.Constant.NONE_CKEYCTX_CKEYCTX_CKEYCTX
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
			PepperedPbkdf2EncoderV1TestInstances.Random.VARS_CONS_NONE_NONE_NONE,
			PepperedPbkdf2EncoderV1TestInstances.Random.VARS_CONS_CTX_CTX_CTX,
			PepperedPbkdf2EncoderV1TestInstances.Random.VARS_CONS_HPWD_HPWD_HPWD,
			PepperedPbkdf2EncoderV1TestInstances.Random.VARS_CONS_HPWDCTX_HPWDCTX_HPWDCTX,
			PepperedPbkdf2EncoderV1TestInstances.Random.VARS_CONS_HKEY_HKEY_HKEY,
			PepperedPbkdf2EncoderV1TestInstances.Random.VARS_CONS_HKEYCTX_HKEYCTX_HKEYCTX,
			PepperedPbkdf2EncoderV1TestInstances.Random.VARS_CONS_CPWD_CPWD_CPWD,
			PepperedPbkdf2EncoderV1TestInstances.Random.VARS_CONS_CPWDCTX_CPWDCTX_CPWDCTX,
			PepperedPbkdf2EncoderV1TestInstances.Random.VARS_CONS_CKEY_CKEY_CKEY,
			PepperedPbkdf2EncoderV1TestInstances.Random.VARS_CONS_CKEYCTX_CKEYCTX_CKEYCTX,

			PepperedPbkdf2EncoderV1TestInstances.Random.VARS_NULL_NULL_NULL,
			PepperedPbkdf2EncoderV1TestInstances.Random.VARS_NONE_NONE_NONE,
			PepperedPbkdf2EncoderV1TestInstances.Random.VARS_CTX_CTX_CTX,
			PepperedPbkdf2EncoderV1TestInstances.Random.VARS_HPWD_HPWD_HPWD,
			PepperedPbkdf2EncoderV1TestInstances.Random.VARS_HPWDCTX_HPWDCTX_HPWDCTX,
			PepperedPbkdf2EncoderV1TestInstances.Random.VARS_HKEY_HKEY_HKEY,
			PepperedPbkdf2EncoderV1TestInstances.Random.VARS_HKEYCTX_HKEYCTX_HKEYCTX,
			PepperedPbkdf2EncoderV1TestInstances.Random.VARS_CPWD_CPWD_CPWD,
			PepperedPbkdf2EncoderV1TestInstances.Random.VARS_CPWDCTX_CPWDCTX_CPWDCTX,
			PepperedPbkdf2EncoderV1TestInstances.Random.VARS_CKEY_CKEY_CKEY,
			PepperedPbkdf2EncoderV1TestInstances.Random.VARS_CKEYCTX_CKEYCTX_CKEYCTX
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
