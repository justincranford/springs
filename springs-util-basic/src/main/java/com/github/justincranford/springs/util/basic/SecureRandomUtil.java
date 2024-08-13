package com.github.justincranford.springs.util.basic;

import java.security.SecureRandom;
import java.util.List;

public class SecureRandomUtil  {
	public static final SecureRandom SECURE_RANDOM = new SecureRandom();

	public static byte[] randomBytes(final int numBytes) {
		final byte[] bytes = new byte[numBytes];
		SECURE_RANDOM.nextBytes(bytes);
		return bytes;
	}
	public static <E extends Enum<?>> E randomEnumElement(final Class<E> enumClass) {
		return randomArrayElement(enumClass.getEnumConstants());
	}
	public static <T> T randomArrayElement(final T[] array) {
		return array[SECURE_RANDOM.nextInt(array.length)];
	}
	public static <E extends List<?>> E randomListElement(final List<E> list) {
		return list.get(SECURE_RANDOM.nextInt(list.size()));
	}
}
