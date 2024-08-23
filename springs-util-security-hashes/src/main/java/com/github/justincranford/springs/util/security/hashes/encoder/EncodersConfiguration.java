package com.github.justincranford.springs.util.security.hashes.encoder;

import java.util.ArrayList;
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
		final Map<String, DerivedSalt>  derivedSaltProps  = props.getEncodersArgon2().getDerivedSalt();
		final Map<String, ConstantSalt> constantSaltProps = props.getEncodersArgon2().getConstantSalt();
		final List<String> keyEncoderConfigNames = new ArrayList<>(props.getKeyEncoder().values());
		Assert.notEmpty(keyEncoderConfigNames, "Key encoder config names must not be empty");
		Collections.reverse(keyEncoderConfigNames);

		final LinkedHashMap<String, KeyEncoder> idToKeyEncoders = new LinkedHashMap<>();
		for (final String keyEncoderConfigName : keyEncoderConfigNames) {
			final EncodersArgon2.DerivedSalt  derivedSalt  = derivedSaltProps.get(keyEncoderConfigName);
			final EncodersArgon2.ConstantSalt constantSalt = constantSaltProps.get(keyEncoderConfigName);
			Assert.isTrue((derivedSalt != null) ^ (constantSalt != null), "Key encoder must be derivedSalt or constantSalt, not null and not both");
			if (derivedSalt != null) {
				idToKeyEncoders.put(derivedSalt.getId(), new KeyEncoder(new Argon2Encoder.DerivedSalt(derivedSalt.getDerivedSaltLength(), derivedSalt.getAssociatedData().getBytes(), derivedSalt.getHashLength(), derivedSalt.getParallelism(), derivedSalt.getMemoryInKB(), derivedSalt.getIterations())));
			} else if (constantSalt != null) {
				idToKeyEncoders.put(constantSalt.getId(), new KeyEncoder(new Argon2Encoder.ConstantSalt(constantSalt.getConstantSalt().getBytes(), constantSalt.getAssociatedData().getBytes(), constantSalt.getHashLength(), constantSalt.getParallelism(), constantSalt.getMemoryInKB(), constantSalt.getIterations())));
			}
		}
		Assert.notEmpty(idToKeyEncoders, "Key encoders map must not be empty");
		return new KeyEncoders(idToKeyEncoders.firstEntry().getKey(), idToKeyEncoders);
	}

	@SuppressWarnings("null")
	@Bean
	public ValueEncoders valueEncoders(final SpringsUtilSecurityHashesProperties props) {
		final Map<String, RandomSalt> randomSaltProps = props.getEncodersArgon2().getRandomSalt();
		final List<String> valueEncoderConfigNames = new ArrayList<>(props.getValueEncoder().values());
		Assert.notEmpty(valueEncoderConfigNames, "Value encoder config names must not be empty");
		Collections.reverse(valueEncoderConfigNames);

		final LinkedHashMap<String, ValueEncoder> idToValueEncoders = new LinkedHashMap<>();
		for (final String valueEncoderConfigName : valueEncoderConfigNames) {
			final EncodersArgon2.RandomSalt randomSalt = randomSaltProps.get(valueEncoderConfigName);
			Assert.isTrue((randomSalt != null), "Value encoder must be randomSalt, not null");
			idToValueEncoders.put(randomSalt.getId(), new ValueEncoder(new Argon2Encoder.RandomSalt(randomSalt.getRandomSaltLength(), randomSalt.getAssociatedData().getBytes(), randomSalt.getHashLength(), randomSalt.getParallelism(), randomSalt.getMemoryInKB(), randomSalt.getIterations())));
		}
		Assert.notEmpty(idToValueEncoders, "Key encoders map must not be empty");
		return new ValueEncoders(idToValueEncoders.firstEntry().getKey(), idToValueEncoders);
	}
}
