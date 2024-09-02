package com.github.justincranford.springs.util.security.hashes.encoder.model;

import jakarta.validation.constraints.NotNull;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.experimental.Accessors;

@RequiredArgsConstructor
@Getter
@Accessors(fluent=true)
public class ConvergentEncryptionAdditionalAuthenticatedDataPepper {
	@NotNull private final Pepper pepper;
}
