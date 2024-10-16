package com.github.justincranford.springs.util.security.hashes.properties;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.stream.Stream;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.PropertySource;
import org.springframework.stereotype.Component;
import org.springframework.validation.annotation.Validated;

import jakarta.annotation.PostConstruct;
import jakarta.validation.ValidationException;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Positive;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;

@ConfigurationProperties(prefix="springs.util.security.hashes",ignoreUnknownFields=false,ignoreInvalidFields=false)
@PropertySource("classpath:springs-util-security-hashes.properties")
@Component
@Validated
@Getter
@Setter
@ToString(callSuper=false)
@Builder(toBuilder=true)
@NoArgsConstructor
@AllArgsConstructor
@SuppressWarnings({"nls", "unchecked", "rawtypes"})
public class SpringsUtilSecurityHashesProperties {
	@PostConstruct
	public void init() {
		// TODO more validation

		this.keyEncoder.entrySet().stream().forEach(keyEncoders -> {
			final int constantSaltCount = this.getEncoders().getArgon2().constantSalt.containsKey(keyEncoders.getValue()) ? 1 : 0;
			final int derivedSaltCount  = this.getEncoders().getArgon2().derivedSalt.containsKey(keyEncoders.getValue())  ? 1 : 0;
			final int randomSaltCount   = this.getEncoders().getArgon2().randomSalt.containsKey(keyEncoders.getValue())   ? 1 : 0;
			final int count             = constantSaltCount + derivedSaltCount + randomSaltCount;
			if (count == 0) {
				throw new ValidationException("No encoder defined for keyEncoder[" + keyEncoders.getKey() + "]=" + keyEncoders.getValue());
			} else if (count > 1) {
				throw new ValidationException("Too many encoders defined for keyEncoder[" + keyEncoders.getKey() + "]=" + keyEncoders.getValue());
			}
		});

		this.valueEncoder.entrySet().stream().forEach(valueEncoders -> {
			final int constantSaltCount = this.getEncoders().getArgon2().constantSalt.containsKey(valueEncoders.getValue()) ? 1 : 0;
			final int derivedSaltCount  = this.getEncoders().getArgon2().derivedSalt.containsKey(valueEncoders.getValue())  ? 1 : 0;
			final int randomSaltCount   = this.getEncoders().getArgon2().randomSalt.containsKey(valueEncoders.getValue())   ? 1 : 0;
			final int count             = constantSaltCount + derivedSaltCount + randomSaltCount;
			if (count == 0) {
				throw new ValidationException("No encoder defined for keyEncoder[" + valueEncoders.getKey() + "]=" + valueEncoders.getValue());
			} else if (count > 1) {
				throw new ValidationException("Too many encoders defined for keyEncoder[" + valueEncoders.getKey() + "]=" + valueEncoders.getValue());
			}
		});
	}

	@NotNull
	@NotEmpty
	@Size(min=Constants.MIN_KEY_ENCODERS, max=Constants.MAX_KEY_ENCODERS)
	private TreeMap<Integer, String> keyEncoder; // rank => configName

	@NotNull
	@NotEmpty
	@Size(min=Constants.MIN_VALUE_ENCODERS, max=Constants.MAX_VALUE_ENCODERS)
	private TreeMap<Integer, String> valueEncoder; // rank => configName

	private Encoders encoders;

	@Component
	@Validated
	@Getter
	@Setter
	@ToString(callSuper=false)
	@Builder(toBuilder=true)
	public static class Encoders {
		public Argon2.AbstractSalt get(final String name) {
			final Map<String, Argon2.AbstractSalt> constantSalt = (Map) this.getArgon2().getConstantSalt();
			final Map<String, Argon2.AbstractSalt>  derivedSalt = (Map) this.getArgon2().getDerivedSalt();
			final Map<String, Argon2.AbstractSalt>   randomSalt = (Map) this.getArgon2().getRandomSalt();
			final List<Argon2.AbstractSalt> matches = Stream.of(constantSalt, derivedSalt, randomSalt)
				.map(map -> map.get(name)).filter(a -> a != null).toList();
			if (matches.size() == 1) {
				return matches.get(0);
			} else if (matches.isEmpty()) {
				throw new RuntimeException("No encoders found. Expected one and only one.");
			}
			throw new RuntimeException("Multiple encoders found. Expected one and only one.");
		}

		private Argon2 argon2;

		@Component
		@Validated
		@Getter
		@Setter
		@ToString(callSuper=false)
		@Builder(toBuilder=true)
		@NoArgsConstructor
		@AllArgsConstructor
		public static class Argon2 {
			@NotNull
			@Builder.Default
			@Size(min=Constants.MIN_CONSTANT_SALT_ENCODERS, max=Constants.MAX_CONSTANT_SALT_ENCODERS)
			private Map<String, ConstantSalt> constantSalt = new HashMap<>(); // configName => settings

			@NotNull
			@NotEmpty
			@Size(min=Constants.MIN_DERIVED_SALT_ENCODERS, max=Constants.MAX_DERIVED_SALT_ENCODERS)
			private Map<String, DerivedSalt> derivedSalt; // configName => settings

			@NotNull
			@NotEmpty
			@Size(min=Constants.MIN_RANDOM_SALT_ENCODERS, max=Constants.MAX_RANDOM_SALT_ENCODERS)
			private Map<String, RandomSalt> randomSalt; // configName => settings

			@Component
			@Validated
			@Getter
			@Setter
			@ToString(callSuper=true)
			@Builder(toBuilder=true)
			@NoArgsConstructor
			@AllArgsConstructor
			public static class ConstantSalt extends AbstractSalt {
				@NotNull
				@Size(min=Constants.MIN_CONSTANT_SALT_LENGTH, max=Constants.MAX_CONSTANT_SALT_LENGTH)
				private String constantSalt;
			}

			@Component
			@Validated
			@Getter
			@Setter
			@ToString(callSuper=true)
			@Builder(toBuilder=true)
			@NoArgsConstructor
			@AllArgsConstructor
			public static class DerivedSalt extends AbstractSalt {
				@NotNull
				@Min(value=Constants.MIN_DERIVED_SALT_LENGTH)
				@Max(value=Constants.MAX_DERIVED_SALT_LENGTH)
				@Positive
				private Integer derivedSaltLength;
			}

			@Component
			@Validated
			@Getter
			@Setter
			@ToString(callSuper=true)
			@Builder(toBuilder=true)
			@NoArgsConstructor
			@AllArgsConstructor
			public static class RandomSalt extends AbstractSalt {
				@NotNull
				@Min(value=Constants.MIN_RANDOM_SALT_LENGTH)
				@Max(value=Constants.MAX_RANDOM_SALT_LENGTH)
				@Positive
				private Integer randomSaltLength;
			}

			@Validated
			@Getter
			@Setter
			@ToString(callSuper=false)
			@NoArgsConstructor
			@AllArgsConstructor
			public static class AbstractSalt {
				@NotNull
				@NotEmpty
				@Size(min=Constants.MIN_ID_LENGTH, max=Constants.MAX_ID_LENGTH)
				private String id;

				@NotNull
				@Size(min=Constants.MIN_ASSOCIATED_DATA_LENGTH, max=Constants.MAX_ASSOCIATED_DATA_LENGTH)
				private String associatedData;

				@NotNull
				@Min(value=Constants.MIN_HASH_LENGTH)
				@Max(value=Constants.MAX_HASH_LENGTH)
				@Positive
				private Integer hashLength;

				@NotNull
				@Min(value=Constants.MIN_PARALLELISM)
				@Max(value=Constants.MAX_PARALLELISM)
				@Positive
				private Integer parallelism;

				@NotNull
				@Min(value=Constants.MIN_MEMORY_IN_KB)
				@Max(value=Constants.MAX_MEMORY_IN_KB)
				@Positive
				private Integer memoryInKB;

				@NotNull
				@Min(value=Constants.MIN_ITERATIONS)
				@Max(value=Constants.MAX_ITERATIONS)
				@Positive
				private Integer iterations;
			}
		}
	}

	private static class Constants {
		private static final int MIN_CONSTANT_SALT_ENCODERS = 0;
		private static final int MAX_CONSTANT_SALT_ENCODERS = 1;

		private static final int MIN_DERIVED_SALT_ENCODERS = 1;
		private static final int MAX_DERIVED_SALT_ENCODERS = 8;

		private static final int MIN_RANDOM_SALT_ENCODERS = 1;
		private static final int MAX_RANDOM_SALT_ENCODERS = 8;

		private static final int MIN_CONSTANT_SALT_LENGTH = 0;
		private static final int MAX_CONSTANT_SALT_LENGTH = 1024;

		private static final int MIN_DERIVED_SALT_LENGTH = 16;
		private static final int MAX_DERIVED_SALT_LENGTH = 1024;

		private static final int MIN_RANDOM_SALT_LENGTH = 16;
		private static final int MAX_RANDOM_SALT_LENGTH = 1024;

		private static final int MIN_ID_LENGTH = 1;
		private static final int MAX_ID_LENGTH = 2;

		private static final int MIN_ASSOCIATED_DATA_LENGTH = 0;
		private static final int MAX_ASSOCIATED_DATA_LENGTH = 1024;

		private static final int MIN_HASH_LENGTH = 16;
		private static final int MAX_HASH_LENGTH = 1024;

		private static final int MIN_PARALLELISM = 1;
		private static final int MAX_PARALLELISM = 16;

		private static final int MIN_MEMORY_IN_KB = 16384;
		private static final int MAX_MEMORY_IN_KB = 65536;

		private static final int MIN_ITERATIONS = 1;
		private static final int MAX_ITERATIONS = 256;

		private static final int MIN_KEY_ENCODERS = 1;
		private static final int MAX_KEY_ENCODERS = MAX_CONSTANT_SALT_ENCODERS + MAX_DERIVED_SALT_ENCODERS + MAX_RANDOM_SALT_ENCODERS;

		private static final int MIN_VALUE_ENCODERS = 1;
		private static final int MAX_VALUE_ENCODERS = MAX_CONSTANT_SALT_ENCODERS + MAX_DERIVED_SALT_ENCODERS + MAX_RANDOM_SALT_ENCODERS;
	}
}
