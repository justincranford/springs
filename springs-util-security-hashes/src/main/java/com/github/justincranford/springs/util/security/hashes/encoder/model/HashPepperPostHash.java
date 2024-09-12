package com.github.justincranford.springs.util.security.hashes.encoder.model;

import jakarta.validation.constraints.NotNull;
import lombok.RequiredArgsConstructor;
import lombok.experimental.Delegate;

@RequiredArgsConstructor
public class HashPepperPostHash implements PepperInterface {
	@Delegate
	@NotNull private final Pepper delegate;
}
