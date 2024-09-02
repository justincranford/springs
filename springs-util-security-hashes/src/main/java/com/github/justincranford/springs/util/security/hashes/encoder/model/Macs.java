package com.github.justincranford.springs.util.security.hashes.encoder.model;

import jakarta.validation.constraints.NotNull;

public record Macs(@NotNull Mac.PepperPreSalt preSalt, @NotNull Mac.PepperPreHash preHash, @NotNull Mac.PepperPostHash postHash) { }
