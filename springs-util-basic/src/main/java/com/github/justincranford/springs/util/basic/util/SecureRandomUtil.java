package com.github.justincranford.springs.util.basic.util;

import java.security.SecureRandom;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import io.micrometer.core.annotation.Timed;
import io.micrometer.observation.annotation.Observed;
import jakarta.annotation.PostConstruct;

@Component
@SuppressWarnings({"static-method"})
public class SecureRandomUtil  {
	public static final SecureRandom SECURE_RANDOM = new SecureRandom();

	private static SecureRandomUtil PROXIED_BEAN; // injected by SelfInjector.postConstruct
	@Component
	 // Use different class to autowire the SecureRandomUtil proxy bean instance, and inject it into a SecureRandomUtil static singleton variable
	private static class SelfInjector { 
	    @Autowired private SecureRandomUtil proxiedBean;
	    @PostConstruct private void postConstruct() { SecureRandomUtil.PROXIED_BEAN = this.proxiedBean; }
	}

	// STATIC METHODS (Static methods are not timed, but calling the bean methods via proxy bean instance allows timing them too)

	public static byte[] staticRandomBytes(final int numBytes) {
		return PROXIED_BEAN.randomBytes(numBytes);
	}
	public static <E extends Enum<?>> E staticRandomEnumElement(final Class<E> enumClass) {
		return PROXIED_BEAN.randomEnumElement(enumClass);
	}
	public static <T> T staticRandomArrayElement(final T[] array) {
		return PROXIED_BEAN.randomArrayElement(array);
	}
	public static <E extends List<?>> E staticRandomListElement(final List<E> list) {
		return PROXIED_BEAN.randomListElement(list);
	}

	// BEAN METHODS (Only bean methods are Timed)

	@Timed
    @Observed
	public byte[] randomBytes(final int numBytes) {
		final byte[] bytes = new byte[numBytes];
		SECURE_RANDOM.nextBytes(bytes);
		return bytes;
	}
	@Timed
	@Observed
	public <E extends Enum<?>> E randomEnumElement(final Class<E> enumClass) {
		return staticRandomArrayElement(enumClass.getEnumConstants());
	}
	@Timed
	@Observed
	public <T> T randomArrayElement(final T[] array) {
		return array[SECURE_RANDOM.nextInt(array.length)];
	}
	@Timed
	@Observed
	public <E extends List<?>> E randomListElement(final List<E> list) {
		return list.get(SECURE_RANDOM.nextInt(list.size()));
	}
}
