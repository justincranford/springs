package com.github.justincranford.springs.util.security.hashes.encoder;

import com.github.justincranford.springs.util.basic.TextCodec;

import jakarta.validation.constraints.NotNull;

public record HashCodec(
	@NotNull TextCodec codec,
	@NotNull String outerSeparator, // between inputs and outputs
	@NotNull String innerSeparator, // within inputs or outputs
	@NotNull Flags flags
) {
	public static record Flags(
		boolean encodeHashInputVariables,
		boolean encodeHashInputConstants
	) {
		public static final Flags NONE = new Flags(false,  false);
		public static final Flags VARS = new Flags(true,   false);
		public static final Flags CONS = new Flags(false,  true);
		public static final Flags BOTH = new Flags(true,   true);
	}
}
