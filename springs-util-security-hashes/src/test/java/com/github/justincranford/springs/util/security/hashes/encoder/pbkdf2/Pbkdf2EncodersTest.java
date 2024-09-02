package com.github.justincranford.springs.util.security.hashes.encoder.pbkdf2;

import static org.assertj.core.api.Assertions.assertThat;

import java.security.Security;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ForkJoinPool;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Supplier;
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

import com.github.justincranford.springs.util.basic.Base64Util;
import com.github.justincranford.springs.util.basic.SecureRandomUtil;
import com.github.justincranford.springs.util.basic.ThreadUtil;
import com.github.justincranford.springs.util.security.hashes.encoder.model.HashEncodeDecode;

import lombok.extern.slf4j.Slf4j;

@Slf4j
@SuppressWarnings({"nls", "boxing", "static-method", "serial"})
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
public class Pbkdf2EncodersTest {
	private static final int REPEATS = 2;

	private static final Map<String, PasswordEncoder> keyEncodersMap = new LinkedHashMap<>() {{
		final AtomicInteger id = new AtomicInteger(0);
		List.of(
			PepperedPbkdf2EncoderV1Instances.Derived.SALTOTH_NULL_NULL_NULL,
			PepperedPbkdf2EncoderV1Instances.Derived.SALTOTH_NONE_NONE_NONE,
			PepperedPbkdf2EncoderV1Instances.Derived.SALTOTH_CTX_CTX_CTX,
			PepperedPbkdf2EncoderV1Instances.Derived.SALTOTH_SK_SK_SK,
			PepperedPbkdf2EncoderV1Instances.Derived.SALTOTH_SKCTX_SKCTX_SKCTX,
			PepperedPbkdf2EncoderV1Instances.Derived.SALT_NULL_NULL_NULL,
			PepperedPbkdf2EncoderV1Instances.Derived.SALT_NONE_NONE_NONE,
			PepperedPbkdf2EncoderV1Instances.Derived.SALT_CTX_CTX_CTX,
			PepperedPbkdf2EncoderV1Instances.Derived.SALT_SK_SK_SK,
			PepperedPbkdf2EncoderV1Instances.Derived.SALT_SKCTX_SKCTX_SKCTX,

			PepperedPbkdf2EncoderV1Instances.Derived.NONE_NULL_NULL_NULL,
			PepperedPbkdf2EncoderV1Instances.Derived.NONE_NONE_NONE_NONE,
			PepperedPbkdf2EncoderV1Instances.Derived.NONE_CTX_CTX_CTX,
			PepperedPbkdf2EncoderV1Instances.Derived.NONE_SK_SK_SK,
			PepperedPbkdf2EncoderV1Instances.Derived.NONE_SKCTX_SKCTX_SKCTX,

			PepperedPbkdf2EncoderV1Instances.Derived.SALT_NULL_NULL_NULL,
			PepperedPbkdf2EncoderV1Instances.Derived.SALT_NONE_NONE_NONE,
			PepperedPbkdf2EncoderV1Instances.Derived.SALT_CTX_CTX_CTX,
			PepperedPbkdf2EncoderV1Instances.Derived.SALT_SK_SK_SK,
			PepperedPbkdf2EncoderV1Instances.Derived.SALT_SKCTX_SKCTX_SKCTX,

			PepperedPbkdf2EncoderV1Instances.Derived.OTH_NULL_NULL_NULL,
			PepperedPbkdf2EncoderV1Instances.Derived.OTH_NONE_NONE_NONE,
			PepperedPbkdf2EncoderV1Instances.Derived.OTH_CTX_CTX_CTX,
			PepperedPbkdf2EncoderV1Instances.Derived.OTH_SK_SK_SK,
			PepperedPbkdf2EncoderV1Instances.Derived.OTH_SKCTX_SKCTX_SKCTX,

			PepperedPbkdf2EncoderV1Instances.Derived.SALTOTH_NULL_NULL_NULL,
			PepperedPbkdf2EncoderV1Instances.Derived.SALTOTH_NONE_NONE_NONE,
			PepperedPbkdf2EncoderV1Instances.Derived.SALTOTH_CTX_CTX_CTX,
			PepperedPbkdf2EncoderV1Instances.Derived.SALTOTH_SK_SK_SK,
			PepperedPbkdf2EncoderV1Instances.Derived.SALTOTH_SKCTX_SKCTX_SKCTX
		).forEach(valueEncoder -> put("k" + id.incrementAndGet(), valueEncoder));
	}};
	private static final String keyEncodersDefault = keyEncodersMap.keySet().iterator().next();
	private static final DelegatingPasswordEncoder keyEncoders = new DelegatingPasswordEncoder(
			keyEncodersMap.keySet().iterator().next(),
		keyEncodersMap
	);

	private static final Map<String, PasswordEncoder> valueEncodersMap = new LinkedHashMap<>() {{
		final AtomicInteger i = new AtomicInteger(0);
		List.of(
			PepperedPbkdf2EncoderV1Instances.Constant.NONE_NULL_NULL_NULL,
			PepperedPbkdf2EncoderV1Instances.Constant.NONE_NONE_NONE_NONE,
			PepperedPbkdf2EncoderV1Instances.Constant.NONE_CTX_CTX_CTX,
			PepperedPbkdf2EncoderV1Instances.Constant.NONE_SK_SK_SK,
			PepperedPbkdf2EncoderV1Instances.Constant.NONE_SKCTX_SKCTX_SKCTX,

			PepperedPbkdf2EncoderV1Instances.Constant.SALT_NULL_NULL_NULL,
			PepperedPbkdf2EncoderV1Instances.Constant.SALT_NONE_NONE_NONE,
			PepperedPbkdf2EncoderV1Instances.Constant.SALT_CTX_CTX_CTX,
			PepperedPbkdf2EncoderV1Instances.Constant.SALT_SK_SK_SK,
			PepperedPbkdf2EncoderV1Instances.Constant.SALT_SKCTX_SKCTX_SKCTX,

			PepperedPbkdf2EncoderV1Instances.Constant.OTH_NULL_NULL_NULL,
			PepperedPbkdf2EncoderV1Instances.Constant.OTH_NONE_NONE_NONE,
			PepperedPbkdf2EncoderV1Instances.Constant.OTH_CTX_CTX_CTX,
			PepperedPbkdf2EncoderV1Instances.Constant.OTH_SK_SK_SK,
			PepperedPbkdf2EncoderV1Instances.Constant.OTH_SKCTX_SKCTX_SKCTX,

			PepperedPbkdf2EncoderV1Instances.Constant.SALTOTH_NULL_NULL_NULL,
			PepperedPbkdf2EncoderV1Instances.Constant.SALTOTH_NONE_NONE_NONE,
			PepperedPbkdf2EncoderV1Instances.Constant.SALTOTH_CTX_CTX_CTX,
			PepperedPbkdf2EncoderV1Instances.Constant.SALTOTH_SK_SK_SK,
			PepperedPbkdf2EncoderV1Instances.Constant.SALTOTH_SKCTX_SKCTX_SKCTX
		).forEach(valueEncoder -> put("v" + i.incrementAndGet(), valueEncoder));
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

	@Test
	public void testPbkdf2ConstantSalt() {
		final Supplier<byte[]> saltSupplier = () -> new byte[16];
		final Pbkdf2ParametersV1 parameters = new Pbkdf2ParametersV1(1, 32, Pbkdf2Algorithm.PBKDF2WithHmacSHA256, HashEncodeDecode.STD_CB_NONE);
		Set<String> encodedHashes = computePbkdf2(REPEATS, parameters, "Hello.World@example.com", saltSupplier);
		assertThat(encodedHashes.size()).isEqualTo(1);
	}

	@Test
	public void testPbkdf2RandomSalt() {
		final Supplier<byte[]> saltSupplier = () -> SecureRandomUtil.randomBytes(16);
		final Pbkdf2ParametersV1 parameters = new Pbkdf2ParametersV1(1, 32, Pbkdf2Algorithm.PBKDF2WithHmacSHA256, HashEncodeDecode.STD_CB_NONE);
		Set<String> encodedHashes = computePbkdf2(REPEATS, parameters, "P@ssw0rd", saltSupplier);
		assertThat(encodedHashes.size()).isEqualTo(REPEATS);
	}

	private Set<String> computePbkdf2(final int repeats, final Pbkdf2ParametersV1 parameters, final String inputBytes, final Supplier<byte[]> saltSupplier) {
		final Set<String> encodedHashes = new HashSet<>();
		for (int i = 0; i < repeats; i++) {
			final byte[] hashBytes = parameters.computeHash(saltSupplier.get(), inputBytes);
			encodedHashes.add(Base64Util.Constants.STD_ENCODER.encodeToString(hashBytes));
		}
		return encodedHashes;
	}
}
