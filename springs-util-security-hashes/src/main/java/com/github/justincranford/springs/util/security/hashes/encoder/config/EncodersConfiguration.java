package com.github.justincranford.springs.util.security.hashes.encoder.config;

import java.util.LinkedHashMap;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;

import com.github.justincranford.springs.util.security.hashes.encoder.argon2.Argon2Encoder;
import com.github.justincranford.springs.util.security.hashes.encoder.model.KeyEncoder;
import com.github.justincranford.springs.util.security.hashes.encoder.model.KeyEncoders;
import com.github.justincranford.springs.util.security.hashes.encoder.model.ValueEncoder;
import com.github.justincranford.springs.util.security.hashes.encoder.model.ValueEncoders;
import com.github.justincranford.springs.util.security.hashes.properties.SpringsUtilSecurityHashesProperties;
import com.github.justincranford.springs.util.security.hashes.properties.SpringsUtilSecurityHashesProperties.Encoders;

@Configuration
@SuppressWarnings({"nls", "static-method", "boxing"})
public class EncodersConfiguration {
	@Bean
	public PasswordEncoder passwordEncoder(final ValueEncoders valueEncoders) {
		return valueEncoders;
	}

	@Bean
	public KeyEncoders keyEncoders(final SpringsUtilSecurityHashesProperties allProps) {
		final LinkedHashMap<String, KeyEncoder> map = new LinkedHashMap<>();
		for (final String name : allProps.getKeyEncoder().reversed().values()) {
			final Encoders.Argon2.AbstractSalt saltProps = allProps.getEncoders().get(name);
			map.put(saltProps.getId(), buildKeyEncoder(saltProps));
		}
		return new KeyEncoders(map.firstEntry().getKey(), map);
	}

	@Bean
	public ValueEncoders valueEncoders(final SpringsUtilSecurityHashesProperties allProps) {
		final LinkedHashMap<String, ValueEncoder> map = new LinkedHashMap<>();
		for (final String name : allProps.getValueEncoder().reversed().values()) {
			final Encoders.Argon2.AbstractSalt saltProps = allProps.getEncoders().get(name);
			map.put(saltProps.getId(), buildValueEncoder(saltProps));
		}
		return new ValueEncoders(map.firstEntry().getKey(), map);
	}

	private KeyEncoder buildKeyEncoder(final Encoders.Argon2.AbstractSalt abstractSalt) {
		if (abstractSalt instanceof Encoders.Argon2.DerivedSalt derivedSalt) {
			return buildKeyEncoder(derivedSalt);
		} else if (abstractSalt instanceof Encoders.Argon2.ConstantSalt constantSalt) {
			return buildKeyEncoder(constantSalt);
		}
		throw new RuntimeException("Inconceivable!");
	}

	private ValueEncoder buildValueEncoder(final Encoders.Argon2.AbstractSalt abstractSalt) {
		if (abstractSalt instanceof Encoders.Argon2.RandomSalt randomSalt) {
			return buildValueEncoder(randomSalt);
		}
		throw new RuntimeException("Inconceivable!");
	}

	private KeyEncoder buildKeyEncoder(final Encoders.Argon2.DerivedSalt derivedSalt) {
		return new KeyEncoder(new Argon2Encoder.DerivedSalt(derivedSalt.getDerivedSaltLength(), derivedSalt.getAssociatedData().getBytes(), derivedSalt.getHashLength(), derivedSalt.getParallelism(), derivedSalt.getMemoryInKB(), derivedSalt.getIterations()));
	}

	private KeyEncoder buildKeyEncoder(final Encoders.Argon2.ConstantSalt constantSalt) {
		return new KeyEncoder(new Argon2Encoder.ConstantSalt(constantSalt.getConstantSalt().getBytes(), constantSalt.getAssociatedData().getBytes(), constantSalt.getHashLength(), constantSalt.getParallelism(), constantSalt.getMemoryInKB(), constantSalt.getIterations()));
	}

	private ValueEncoder buildValueEncoder(final Encoders.Argon2.RandomSalt randomSalt) {
		return new ValueEncoder(new Argon2Encoder.RandomSalt(randomSalt.getRandomSaltLength(), randomSalt.getAssociatedData().getBytes(), randomSalt.getHashLength(), randomSalt.getParallelism(), randomSalt.getMemoryInKB(), randomSalt.getIterations()));
	}
}
