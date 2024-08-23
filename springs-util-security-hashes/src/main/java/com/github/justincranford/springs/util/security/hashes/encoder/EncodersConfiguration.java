package com.github.justincranford.springs.util.security.hashes.encoder;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
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
import com.github.justincranford.springs.util.security.hashes.properties.SpringsUtilSecurityHashesProperties.EncodersArgon2;
import com.github.justincranford.springs.util.security.hashes.properties.SpringsUtilSecurityHashesProperties.EncodersArgon2.ConstantSalt;
import com.github.justincranford.springs.util.security.hashes.properties.SpringsUtilSecurityHashesProperties.EncodersArgon2.DerivedSalt;
import com.github.justincranford.springs.util.security.hashes.properties.SpringsUtilSecurityHashesProperties.EncodersArgon2.RandomSalt;

@Configuration
@SuppressWarnings({"nls", "static-method", "boxing"})
public class EncodersConfiguration {
	@Bean
	public PasswordEncoder passwordEncoder(final ValueEncoders valueEncoders) {
		return valueEncoders;
	}

	@Bean
	public KeyEncoders keyEncoders(final SpringsUtilSecurityHashesProperties props) {
		final Map<String, DerivedSalt>  derivedSaltPropsMap  = props.getEncodersArgon2().getDerivedSalt();
		final Map<String, ConstantSalt> constantSaltPropsMap = props.getEncodersArgon2().getConstantSalt();

		final LinkedHashMap<String, KeyEncoder> idToKeyEncoders = new LinkedHashMap<>();
		for (final String name : reverse(props.getKeyEncoder().values())) {
			final EncodersArgon2.DerivedSalt derivedSaltProps = derivedSaltPropsMap.get(name);
			final EncodersArgon2.ConstantSalt constantSaltProps = constantSaltPropsMap.get(name);
			Assert.isTrue((derivedSaltProps != null) ^ (constantSaltProps != null), "KeyEncoder must be DerivedSalt or ConstantSalt");
			if (derivedSaltProps != null) {
				idToKeyEncoders.put(derivedSaltProps.getId(), buildKeyEncoder(derivedSaltProps));
			} else if (constantSaltProps != null) {
				idToKeyEncoders.put(constantSaltProps.getId(), buildKeyEncoder(constantSaltProps));
			} else {
				throw new RuntimeException("Impossible");
			}
		}
		Assert.notEmpty(idToKeyEncoders, "KeyEncoders map must not be empty");
		return new KeyEncoders(idToKeyEncoders.firstEntry().getKey(), idToKeyEncoders);
	}

	@Bean
	public ValueEncoders valueEncoders(final SpringsUtilSecurityHashesProperties props) {
		final Map<String, RandomSalt> randomSaltPropsMap = props.getEncodersArgon2().getRandomSalt();

		final LinkedHashMap<String, ValueEncoder> idToValueEncoders = new LinkedHashMap<>();
		for (final String name : reverse(props.getValueEncoder().values())) {
			final EncodersArgon2.RandomSalt randomSalt = randomSaltPropsMap.get(name);
			Assert.isTrue((randomSalt != null), "ValueEncoder must be RandomSalt");
			if (randomSalt != null) {
				idToValueEncoders.put(randomSalt.getId(), buildValueEncoder(randomSalt));
			} else {
				throw new RuntimeException("Impossible");
			}
		}
		Assert.notEmpty(idToValueEncoders, "ValueEncoders map must not be empty");
		return new ValueEncoders(idToValueEncoders.firstEntry().getKey(), idToValueEncoders);
	}

	private List<String> reverse(final Collection<String> configNames) {
		final List<String> valueEncoderConfigNames = new ArrayList<>(configNames);
		Assert.notEmpty(valueEncoderConfigNames, "Config names must not be empty");
		Collections.reverse(valueEncoderConfigNames);
		return valueEncoderConfigNames;
	}

	private KeyEncoder buildKeyEncoder(final EncodersArgon2.DerivedSalt derivedSalt) {
		return new KeyEncoder(new Argon2Encoder.DerivedSalt(derivedSalt.getDerivedSaltLength(), derivedSalt.getAssociatedData().getBytes(), derivedSalt.getHashLength(), derivedSalt.getParallelism(), derivedSalt.getMemoryInKB(), derivedSalt.getIterations()));
	}

	private KeyEncoder buildKeyEncoder(final EncodersArgon2.ConstantSalt constantSalt) {
		return new KeyEncoder(new Argon2Encoder.ConstantSalt(constantSalt.getConstantSalt().getBytes(), constantSalt.getAssociatedData().getBytes(), constantSalt.getHashLength(), constantSalt.getParallelism(), constantSalt.getMemoryInKB(), constantSalt.getIterations()));
	}

	private ValueEncoder buildValueEncoder(final EncodersArgon2.RandomSalt randomSalt) {
		return new ValueEncoder(new Argon2Encoder.RandomSalt(randomSalt.getRandomSaltLength(), randomSalt.getAssociatedData().getBytes(), randomSalt.getHashLength(), randomSalt.getParallelism(), randomSalt.getMemoryInKB(), randomSalt.getIterations()));
	}
}
