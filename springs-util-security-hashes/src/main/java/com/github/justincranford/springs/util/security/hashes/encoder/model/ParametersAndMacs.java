package com.github.justincranford.springs.util.security.hashes.encoder.model;

import jakarta.validation.constraints.NotNull;

public record ParametersAndMacs(@NotNull Parameters parameters, @NotNull Macs macs) { }
