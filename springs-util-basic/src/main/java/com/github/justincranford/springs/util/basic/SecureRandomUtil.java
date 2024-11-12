package com.github.justincranford.springs.util.basic;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.List;

import com.github.justincranford.springs.util.basic.Base64Util.EncoderDecoder;

@SuppressWarnings({"nls"})
public class SecureRandomUtil  {
	public static final SecureRandom SECURE_RANDOM = new SecureRandom();

	public static byte[] randomBytes(final int randomBytes) {
		final byte[] bytes = new byte[randomBytes];
		SECURE_RANDOM.nextBytes(bytes);
		return bytes;
	}

	public static String randomString(final EncoderDecoder encoderDecoder, final int randomBytesLength) {
		return encoderDecoder.encodeToString(SecureRandomUtil.randomBytes(randomBytesLength));
	}

	public static String randomEmailAddress() {
		return "user-" + randomString(Base64Util.URL, 32) + "@example.com";
	}

	/**
	 * Useful for generating random values that behave similar to UUID Type 7, which are performant for BTREE indexes.
	 * UUID Type 4 values don't cluster together in a BTREE index, due to randomness, which leads to fragmentation.
	 * UUID Type 7 values do    cluster together in a BTREE index, due to timestamp-based prefix, which mitigates fragmentation.
	 * 
	 * Prefixing random bytes with first N highest-order bytes of an 8-byte timestamp should lead to clustering by these time buckets:
	 * 
	 * First 1 bytes: 72,057,594,037,927,936 msec ≈ ~2,284,931.32 Years
	 * First 2 bytes:    281,474,976,710,656 msec ≈     ~8,925.51 Years
	 * First 3 bytes:      1,073,741,824,000 msec =        ~34.05 Years
	 * First 4 bytes:          4,294,967,296 msec = 49 Days 417 Minutes 59.296 Seconds
	 * First 5 bytes:             16,777,216 msec =  4 Hours 39 Minutes 37.216 Seconds
	 * First 6 bytes:                 65,536 msec = 65.536 sec
	 * First 7 bytes:                    256 msec =  0.256 sec
	 * First 8 bytes:                      1 msec =  0.001 sec
	 * @param timestampBytes Number of highest-order bytes from 8-byte timestamp in milliseconds
	 * @param randomBytes Random number of bytes
	 * @return Concatenation of timestamp bytes and random bytes
	 */
	public static byte[] timeStampBytesAndRandomBytes(final int timestampBytes, final int randomBytes) {
		if ((timestampBytes < 4) || (timestampBytes > 8)) {
			throw new RuntimeException("Timestamp bytes must be 4-8 inclusive");
		} else if ((timestampBytes < 1) || (timestampBytes > 128)) {
			throw new RuntimeException("Random bytes must be 1-128 inclusive");
		}
	    final byte[] timestamp = ByteBuffer.allocate(8).order(ByteOrder.BIG_ENDIAN).putLong(Instant.now().toEpochMilli()).array();

	    // overwrite beginning of result with N highest-order bytes of the 8-byte timestamp
		final byte[] result = randomBytes(timestampBytes + randomBytes); // EX: 8+32 => 40 bytes
	    System.arraycopy(timestamp, 0, result, 0, timestampBytes);
	    return result;
	}
	public static <E extends Enum<?>> E randomEnumElement(final Class<E> enumClass) {
		return randomArrayElement(enumClass.getEnumConstants());
	}
	public static <T> T randomArrayElement(final T[] array) {
		return array[SECURE_RANDOM.nextInt(array.length)];
	}
	public static <E> E randomListElement(final List<E> list) {
		return list.get(SECURE_RANDOM.nextInt(list.size()));
	}
}
