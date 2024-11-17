package com.github.justincranford.springs.util.security.hashes.encoder.model;

import com.github.justincranford.springs.util.basic.StringUtil;
import com.github.justincranford.springs.util.security.hashes.encoder.HashCodec;
import com.github.justincranford.springs.util.security.hashes.encoder.pbkdf2.Pbkdf2AlgorithmV1;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import lombok.Getter;
import lombok.experimental.Accessors;

import java.util.List;

@Getter
@Accessors(fluent = true)
public abstract class HashInputConstants {
    @NotNull
    private final HashAlgorithm algorithm;
    @NotNull
    private final HashCodec codec;
    @Min(CommonConstraints.MIN_HASH_BYTES_LEN)
    private final int hashBytesLen;

    protected HashInputConstants(
        @NotNull final Pbkdf2AlgorithmV1 algorithm0,
        @NotNull final HashCodec codec0,
        @Min(CommonConstraints.MIN_HASH_BYTES_LEN) final int hashBytesLen0
    ) {
        this.algorithm = algorithm0;
        this.codec = codec0;
        this.hashBytesLen = hashBytesLen0;
    }

    public static void appendEncodeInput(@NotNull final HashInputConstants expectedHashInputConstants, @NotEmpty final List<String> hashInputsValues) {
        if (expectedHashInputConstants.codec().flags().encodeHashInputConstants()) {
            hashInputsValues.addAll(expectedHashInputConstants.canonicalObjects());
        }
    }

    @NotEmpty
    public abstract List<String> canonicalObjects();

    public static HashInputConstants decode(final HashInputConstants expectedHashInputConstants, final List<String> hashInputPartsEncoded) {
        return expectedHashInputConstants.decode(hashInputPartsEncoded);
    }

    @NotEmpty
    public abstract HashInputConstants decode(@NotEmpty List<String> parts);

    @NotNull
    public abstract byte[] canonicalBytes();

    @NotNull
    public abstract byte[] compute(@NotNull final byte[] variableInputConstantsBytes, @NotNull final CharSequence inputString);

    @NotNull
    public abstract Boolean recompute( // TODO abstract
                                       @Min(CommonConstraints.MIN_HASH_INPUT_VARIABLES_BYTES_LEN) final int expectedHashInputVariablesBytesLength,
                                       @Min(CommonConstraints.MIN_HASH_INPUT_VARIABLES_BYTES_LEN) final int actualHashInputVariablesBytesLength,
                                       @NotNull final HashInputConstants actualHashInputConstants,
                                       @Min(CommonConstraints.MIN_HASH_BYTES_LEN) final int expectedHashBytesLength,
                                       @Min(CommonConstraints.MIN_HASH_BYTES_LEN) final int actualHashBytesLength
    );

    public List<String> splitInputs(@NotNull final String hashInputsEncoded) {
        return StringUtil.split(hashInputsEncoded, this.codec().innerSeparator());
    }

    public String encode(@NotEmpty final byte[] plain) {
        return this.codec().codec().encodeToString(plain);
    }

    public byte[] decode(@NotEmpty final String encoded) {
        return this.codec().codec().decodeFromString(encoded);
    }

    public static class CommonConstraints {
        public static final int MIN_HASH_INPUT_VARIABLES_BYTES_LEN = 0;    // Absolute Min (Testing): 0-bit,  Recommended Min (Production): 256-bit/32-bytes
        public static final int MIN_HASH_BYTES_LEN = 8;    // Absolute Min (Testing): 64-bit, Recommended Min (Production): 256-bit/32-bytes
    }
}
