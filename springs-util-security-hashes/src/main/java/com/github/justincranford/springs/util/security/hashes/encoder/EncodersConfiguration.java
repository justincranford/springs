package com.github.justincranford.springs.util.security.hashes.encoder;

import java.util.LinkedHashMap;
import java.util.Map;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.util.Assert;

import com.github.justincranford.springs.util.security.hashes.encoder.argon2.Argon2Encoder;
import com.github.justincranford.springs.util.security.hashes.encoder.model.KeyEncoder;
import com.github.justincranford.springs.util.security.hashes.encoder.model.KeyEncoders;
import com.github.justincranford.springs.util.security.hashes.encoder.model.ValueEncoder;
import com.github.justincranford.springs.util.security.hashes.encoder.model.ValueEncoders;
import com.github.justincranford.springs.util.security.hashes.properties.SpringsUtilSecurityHashesProperties;
import com.github.justincranford.springs.util.security.hashes.properties.SpringsUtilSecurityHashesProperties.Encoders;
import com.github.justincranford.springs.util.security.hashes.properties.SpringsUtilSecurityHashesProperties.Encoders.Argon2.ConstantSalt;
import com.github.justincranford.springs.util.security.hashes.properties.SpringsUtilSecurityHashesProperties.Encoders.Argon2.DerivedSalt;
import com.github.justincranford.springs.util.security.hashes.properties.SpringsUtilSecurityHashesProperties.Encoders.Argon2.RandomSalt;

@Configuration
@SuppressWarnings({"nls", "static-method", "boxing"})
public class EncodersConfiguration {
	@Bean
	public PasswordEncoder passwordEncoder(final ValueEncoders valueEncoders) {
		return valueEncoders;
	}

	@Bean
	public KeyEncoders keyEncoders(final SpringsUtilSecurityHashesProperties props) {
		final Map<String, DerivedSalt>  derivedSaltPropsMap  = props.getEncoders().getArgon2().getDerivedSalt();
		final Map<String, ConstantSalt> constantSaltPropsMap = props.getEncoders().getArgon2().getConstantSalt();

		final LinkedHashMap<String, KeyEncoder> idToKeyEncoders = new LinkedHashMap<>();
		for (final String name : props.getKeyEncoder().reversed().values()) {
			final Encoders.Argon2.DerivedSalt derivedSaltProps = derivedSaltPropsMap.get(name);
			final Encoders.Argon2.ConstantSalt constantSaltProps = constantSaltPropsMap.get(name);
			Assert.isTrue((derivedSaltProps != null) ^ (constantSaltProps != null), "KeyEncoder must be DerivedSalt or ConstantSalt");
			if (derivedSaltProps != null) {
				idToKeyEncoders.put(derivedSaltProps.getId(), buildKeyEncoder(derivedSaltProps));
			} else if (constantSaltProps != null) {
				idToKeyEncoders.put(constantSaltProps.getId(), buildKeyEncoder(constantSaltProps));
			} else {
				throw new RuntimeException("Inconceivable!");
			}
		}
		Assert.notEmpty(idToKeyEncoders, "KeyEncoders map must not be empty");
		return new KeyEncoders(idToKeyEncoders.firstEntry().getKey(), idToKeyEncoders);
	}

	@Bean
	public ValueEncoders valueEncoders(final SpringsUtilSecurityHashesProperties props) {
		final Map<String, RandomSalt> randomSaltPropsMap = props.getEncoders().getArgon2().getRandomSalt();

		final LinkedHashMap<String, ValueEncoder> idToValueEncoders = new LinkedHashMap<>();
		for (final String name : props.getValueEncoder().reversed().values()) {
			final Encoders.Argon2.RandomSalt randomSalt = randomSaltPropsMap.get(name);
			Assert.isTrue((randomSalt != null), "ValueEncoder must be RandomSalt");
			if (randomSalt != null) {
				idToValueEncoders.put(randomSalt.getId(), buildValueEncoder(randomSalt));
			} else {
				throw new RuntimeException("Inconceivable!");
			}
		}
		Assert.notEmpty(idToValueEncoders, "ValueEncoders map must not be empty");
		return new ValueEncoders(idToValueEncoders.firstEntry().getKey(), idToValueEncoders);
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
