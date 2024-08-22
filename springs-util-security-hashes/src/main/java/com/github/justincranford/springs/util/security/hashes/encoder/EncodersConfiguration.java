package com.github.justincranford.springs.util.security.hashes.encoder;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.DelegatingPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import com.github.justincranford.springs.util.security.hashes.encoder.argon2.Argon2Encoder;
import com.github.justincranford.springs.util.security.hashes.properties.SpringsUtilSecurityHashesProperties;
import com.github.justincranford.springs.util.security.hashes.properties.SpringsUtilSecurityHashesProperties.EncodersArgon2;

import lombok.Getter;

@Configuration
@SuppressWarnings({"deprecation", "static-method"})
public class EncodersConfiguration {
	// TODO upgradeEncoding true
	private static final PasswordEncoder NOOP_PASSWORD_ENCODER = NoOpPasswordEncoder.getInstance();

	@Bean
	public PasswordEncoder passwordEncoder(final ValueEncoders valueEncoders) {
		return valueEncoders;
	}

	@Bean
	public KeyEncoders keyEncoders(final SpringsUtilSecurityHashesProperties props) {
		final LinkedHashMap<String, PasswordEncoder> idToKeyEncoders = new LinkedHashMap<>();

		final List<String> keyEncoderConfigNames = new ArrayList<>(props.getKeyEncoder().values());
		if (keyEncoderConfigNames.isEmpty()) {
			throw new RuntimeException();
		}
		Collections.reverse(keyEncoderConfigNames);
		for (final String keyEncoderConfigName : keyEncoderConfigNames) {
			final EncodersArgon2.DerivedSalt  derivedSaltProps  = props.getEncodersArgon2().getDerivedSalt().get(keyEncoderConfigName);
			final EncodersArgon2.ConstantSalt constantSaltProps = props.getEncodersArgon2().getConstantSalt().get(keyEncoderConfigName);
			final Argon2Encoder.CustomArgon2Encoder keyEncoder;
			final String id;
			if ((derivedSaltProps != null) && (constantSaltProps != null)) {
				throw new RuntimeException();
			} else if (derivedSaltProps != null) {
				id = derivedSaltProps.getId();
				keyEncoder = new Argon2Encoder.DerivedSalt(derivedSaltProps.getContext().getBytes(), derivedSaltProps.getMinimumDerivedSaltLength(), derivedSaltProps.getHashLength(), derivedSaltProps.getParallelism(), derivedSaltProps.getMemoryInKB(), derivedSaltProps.getIterations());
			} else if (constantSaltProps != null) {
				id = constantSaltProps.getId();
				keyEncoder = new Argon2Encoder.ConstantSalt(constantSaltProps.getContext().getBytes(), constantSaltProps.getConstantSalt().getBytes(), constantSaltProps.getHashLength(), constantSaltProps.getParallelism(), constantSaltProps.getMemoryInKB(), constantSaltProps.getIterations());
			} else {
				throw new RuntimeException();
			}
			idToKeyEncoders.put(id, keyEncoder);
		}
		if (idToKeyEncoders.isEmpty()) {
			throw new RuntimeException();
		}
		return new KeyEncoders(idToKeyEncoders.firstEntry().getKey(), idToKeyEncoders);
	}

	@Bean
	public ValueEncoders valueEncoders(final SpringsUtilSecurityHashesProperties props) {
		final LinkedHashMap<String, PasswordEncoder> idToValueEncoders = new LinkedHashMap<>();

		final List<String> valueEncoderConfigNames = new ArrayList<>(props.getValueEncoder().values());
		if (valueEncoderConfigNames.isEmpty()) {
			throw new RuntimeException();
		}
		Collections.reverse(valueEncoderConfigNames);
		for (final String valueEncoderConfigName : valueEncoderConfigNames) {
			final EncodersArgon2.RandomSalt randomSaltProps = props.getEncodersArgon2().getRandomSalt().get(valueEncoderConfigName);
			final Argon2Encoder.CustomArgon2Encoder valueEncoder;
			if (randomSaltProps == null) {
				throw new RuntimeException();
			}
			final String id = randomSaltProps.getId();
			valueEncoder = new Argon2Encoder.RandomSalt(randomSaltProps.getContext().getBytes(), randomSaltProps.getRandomSaltLength(), randomSaltProps.getHashLength(), randomSaltProps.getParallelism(), randomSaltProps.getMemoryInKB(), randomSaltProps.getIterations());
			idToValueEncoders.put(id, valueEncoder);
		}
		if (idToValueEncoders.isEmpty()) {
			throw new RuntimeException();
		}
		return new ValueEncoders(idToValueEncoders.firstEntry().getKey(), idToValueEncoders);
	}

	@Getter
	public static class KeyEncoders extends DelegatingPasswordEncoder {
		private final String currentIdForEncode;
		private final Map<String, PasswordEncoder> currentIdToKeyEncoders;
		public KeyEncoders(final String id, final Map<String, PasswordEncoder> map) {
			super(id, map);
			this.currentIdForEncode = id;
			this.currentIdToKeyEncoders = map;
			super.setDefaultPasswordEncoderForMatches(NOOP_PASSWORD_ENCODER);
		}
	}

	@Getter
	public static class ValueEncoders extends DelegatingPasswordEncoder {
		private final String currentIdForEncode;
		private final Map<String, PasswordEncoder> currentIdToValueEncoders;
		public ValueEncoders(final String id, final Map<String, PasswordEncoder> map) {
			super(id, map);
			this.currentIdForEncode = id;
			this.currentIdToValueEncoders = map;
			super.setDefaultPasswordEncoderForMatches(NOOP_PASSWORD_ENCODER);
		}
	}
}
