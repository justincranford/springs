package com.github.justincranford.springs.util.security.encoder;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.security.crypto.password.DelegatingPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import com.github.justincranford.springs.util.security.encoder.argon2.Argon2Encoder;

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
		private final LinkedHashMap<String, PasswordEncoder> idToValueEncoders     = toLinkedHashMap(keyEncoder1(), keyEncoder0());
		private final String                                 defaultValueEncoderId = this.idToValueEncoders.firstEntry().getKey();
		@Bean
		public DelegatingPasswordEncoder keyEncoders() {
			final DelegatingPasswordEncoder delegatingPasswordEncoder = new DelegatingPasswordEncoder(this.defaultValueEncoderId, this.idToValueEncoders);
			delegatingPasswordEncoder.setDefaultPasswordEncoderForMatches(NOOP_PASSWORD_ENCODER);
			return delegatingPasswordEncoder;
		}
		// @VisibleForTesting
		public IdAndPasswordEncoder keyEncoder() {
			return keyEncoder1();
		}
		// @VisibleForTesting
		public IdAndPasswordEncoder keyEncoder1() {
			final int minimumDerivedSaltLength = 16;
			final byte[] contextBytes = "context1".getBytes();
			return new IdAndPasswordEncoder("1", new Argon2Encoder.DerivedSalt(contextBytes, minimumDerivedSaltLength, 32, 1, 1 << 14, 2));
		}
		// @VisibleForTesting
		public IdAndPasswordEncoder keyEncoder0() {
			final byte[] constantSaltBytes = "Constant16-Bytes".getBytes();
			final byte[] contextBytes = "context0".getBytes();
			return new IdAndPasswordEncoder("0", new Argon2Encoder.ConstantSalt(contextBytes, constantSaltBytes, 16, 1, 1 << 13, 1));
		}
	}

	@Configuration
	public class ValueEncodersConfiguration {
		private final LinkedHashMap<String, PasswordEncoder> idToKeyEncoders     = toLinkedHashMap(valueEncoder1(), valueEncoder0());
		private final String                                 defaultKeyEncoderId = this.idToKeyEncoders.firstEntry().getKey();
		@Bean
		public DelegatingPasswordEncoder valueEncoders() {
			final DelegatingPasswordEncoder delegatingPasswordEncoder = new DelegatingPasswordEncoder(this.defaultKeyEncoderId, this.idToKeyEncoders);
			delegatingPasswordEncoder.setDefaultPasswordEncoderForMatches(NOOP_PASSWORD_ENCODER);
			return delegatingPasswordEncoder;
		}
		// @VisibleForTesting
		public IdAndPasswordEncoder valueEncoder() {
			return new IdAndPasswordEncoder(this.defaultKeyEncoderId, this.idToKeyEncoders.get(this.defaultKeyEncoderId));
		}
		// @VisibleForTesting
		public IdAndPasswordEncoder valueEncoder1() {
			final byte[] contextBytes = "context1".getBytes();
			return new IdAndPasswordEncoder("1", new Argon2Encoder.RandomSalt(contextBytes, 16, 32, 1, 1 << 14, 2));
		}
		// @VisibleForTesting
		public IdAndPasswordEncoder valueEncoder0() {
			final byte[] contextBytes = "context0".getBytes();
			return new IdAndPasswordEncoder("0", new Argon2Encoder.RandomSalt(contextBytes, 16, 32, 1, 1 << 14, 2));
		}
	}

	private static LinkedHashMap<String, PasswordEncoder> toLinkedHashMap(final IdAndPasswordEncoder...idAndPasswordEncoders) {
		return Stream.of(idAndPasswordEncoders)
				.map(idAndPasswordEncoder -> Map.entry(idAndPasswordEncoder.id(), idAndPasswordEncoder.encoder()))
				.collect(Collectors.toMap(
                    Map.Entry::getKey,
                    Map.Entry::getValue,
                    (encoderA, encoderB) -> { throw new IllegalStateException("Error"); },
                    LinkedHashMap::new
                )
			);
	}

	private record IdAndPasswordEncoder(String id, PasswordEncoder encoder) { }
}
