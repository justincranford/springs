package com.github.justincranford.springs.util.security.properties;

import java.util.HashMap;
import java.util.Map;
import java.util.TreeMap;

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

@ConfigurationProperties(prefix="springs.util.security",ignoreUnknownFields=false,ignoreInvalidFields=false)
@PropertySource("classpath:springs-util-security.properties")
@Component
@Validated
@Getter
@Setter
@ToString(callSuper=false)
@Builder(toBuilder=true)
@NoArgsConstructor
@AllArgsConstructor
@SuppressWarnings({"nls"})
public class SpringsUtilSecurityProperties {
	@PostConstruct
	public void init() {
		// TODO more validation

		this.keyEncoder.entrySet().stream().forEach(keyEncoders -> {
			final int constantSaltCount = this.encodersArgon2.constantSalt.containsKey(keyEncoders.getValue()) ? 1 : 0;
			final int derivedSaltCount  = this.encodersArgon2.derivedSalt.containsKey(keyEncoders.getValue())  ? 1 : 0;
			final int randomSaltCount   = this.encodersArgon2.randomSalt.containsKey(keyEncoders.getValue())   ? 1 : 0;
			final int count             = constantSaltCount + derivedSaltCount + randomSaltCount;
			if (count == 0) {
				throw new ValidationException("No encoder defined for keyEncoder[" + keyEncoders.getKey() + "]=" + keyEncoders.getValue());
			} else if (count > 1) {
				throw new ValidationException("Too many encoders defined for keyEncoder[" + keyEncoders.getKey() + "]=" + keyEncoders.getValue());
			}
		});

		this.valueEncoder.entrySet().stream().forEach(valueEncoders -> {
			final int constantSaltCount = this.encodersArgon2.constantSalt.containsKey(valueEncoders.getValue()) ? 1 : 0;
			final int derivedSaltCount  = this.encodersArgon2.derivedSalt.containsKey(valueEncoders.getValue())  ? 1 : 0;
			final int randomSaltCount   = this.encodersArgon2.randomSalt.containsKey(valueEncoders.getValue())   ? 1 : 0;
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

	private EncodersArgon2 encodersArgon2;

	@Component
	@Validated
	@Getter
	@Setter
	@ToString(callSuper=false)
	@Builder(toBuilder=true)
	@NoArgsConstructor
	@AllArgsConstructor
	public static class EncodersArgon2 {
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
			private Integer minimumDerivedSaltLength;
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
			@Size(min=Constants.MIN_CONTEXT_LENGTH, max=Constants.MAX_CONTEXT_LENGTH)
			private String context;

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

		private static final int MIN_CONTEXT_LENGTH = 0;
		private static final int MAX_CONTEXT_LENGTH = 1024;

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
