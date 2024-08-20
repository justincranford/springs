package com.github.justincranford.springs.util.security.encoder;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.security.crypto.password.DelegatingPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import com.github.justincranford.springs.util.security.encoder.argon2.Argon2Encoder;
import com.github.justincranford.springs.util.security.properties.SpringsUtilSecurityProperties;
import com.github.justincranford.springs.util.security.properties.SpringsUtilSecurityProperties.EncodersArgon2;

@Configuration
@Import({EncodersConfiguration.KeyEncodersConfiguration.class, EncodersConfiguration.ValueEncodersConfiguration.class})
@SuppressWarnings({"deprecation", "nls", "static-method"})
public class EncodersConfiguration {
	// TODO upgradeEncoding true
	private static final PasswordEncoder NOOP_PASSWORD_ENCODER = NoOpPasswordEncoder.getInstance();

	@Bean
	public PasswordEncoder passwordEncoder(final DelegatingPasswordEncoder valueEncoders) {
		return valueEncoders;
	}

	@Configuration
	public class KeyEncodersConfiguration {
		private final LinkedHashMap<String, PasswordEncoder> idToKeyEncoders = new LinkedHashMap<>();
		public KeyEncodersConfiguration(final SpringsUtilSecurityProperties props) {
			final List<String> keyEncoderConfigNames = new ArrayList<>(props.getKeyEncoder().values());
			Collections.reverse(keyEncoderConfigNames);
			for (final String keyEncoderConfigName : keyEncoderConfigNames) {
				final EncodersArgon2.ConstantSalt constantSaltProps = props.getEncodersArgon2().getConstantSalt().get(keyEncoderConfigName);
				final EncodersArgon2.DerivedSalt derivedSaltProps = props.getEncodersArgon2().getDerivedSalt().get(keyEncoderConfigName);
				final Argon2Encoder.CustomArgon2Encoder keyEncoder;
				final String id;
				if ((constantSaltProps == null) && (derivedSaltProps == null)) {
					throw new RuntimeException();
				} else if ((constantSaltProps != null) && (derivedSaltProps != null)) {
					throw new RuntimeException();
				} else if (constantSaltProps != null) {
					id = constantSaltProps.getId();
					keyEncoder = new Argon2Encoder.ConstantSalt(constantSaltProps.getContext().getBytes(), constantSaltProps.getConstantSalt().getBytes(), constantSaltProps.getHashLength(), constantSaltProps.getParallelism(), constantSaltProps.getMemoryInKB(), constantSaltProps.getIterations());
				} else {
					id = derivedSaltProps.getId();
					keyEncoder = new Argon2Encoder.DerivedSalt(derivedSaltProps.getContext().getBytes(), derivedSaltProps.getMinimumDerivedSaltLength(), derivedSaltProps.getHashLength(), derivedSaltProps.getParallelism(), derivedSaltProps.getMemoryInKB(), derivedSaltProps.getIterations());
				}
				this.idToKeyEncoders.put(id, keyEncoder);
			}
		}
		@Bean
		public DelegatingPasswordEncoder keyEncoders() {
			final DelegatingPasswordEncoder delegatingPasswordEncoder = new DelegatingPasswordEncoder(this.idToKeyEncoders.firstEntry().getKey(), this.idToKeyEncoders);
			delegatingPasswordEncoder.setDefaultPasswordEncoderForMatches(NOOP_PASSWORD_ENCODER);
			return delegatingPasswordEncoder;
		}
	}

	@Configuration
	public class ValueEncodersConfiguration {
		private final LinkedHashMap<String, PasswordEncoder> idToValueEncoders = new LinkedHashMap<>();
		public ValueEncodersConfiguration(final SpringsUtilSecurityProperties props) {
			final List<String> valueEncoderConfigNames = new ArrayList<>(props.getValueEncoder().values());
			Collections.reverse(valueEncoderConfigNames);
			for (final String valueEncoderConfigName : valueEncoderConfigNames) {
				final EncodersArgon2.RandomSalt randomSaltProps = props.getEncodersArgon2().getRandomSalt().get(valueEncoderConfigName);
				final Argon2Encoder.CustomArgon2Encoder keyEncoder;
				final String id;
				if (randomSaltProps == null) {
					throw new RuntimeException();
				} else {
					id = randomSaltProps.getId();
					keyEncoder = new Argon2Encoder.DerivedSalt(randomSaltProps.getContext().getBytes(), randomSaltProps.getRandomSaltLength(), randomSaltProps.getHashLength(), randomSaltProps.getParallelism(), randomSaltProps.getMemoryInKB(), randomSaltProps.getIterations());
				}
				this.idToValueEncoders.put(id, keyEncoder);
			}
		}
		@Bean
		public DelegatingPasswordEncoder valueEncoders() {
			final DelegatingPasswordEncoder delegatingPasswordEncoder = new DelegatingPasswordEncoder(this.idToValueEncoders.firstEntry().getKey(), this.idToValueEncoders);
			delegatingPasswordEncoder.setDefaultPasswordEncoderForMatches(NOOP_PASSWORD_ENCODER);
			return delegatingPasswordEncoder;
		}
	}
}
