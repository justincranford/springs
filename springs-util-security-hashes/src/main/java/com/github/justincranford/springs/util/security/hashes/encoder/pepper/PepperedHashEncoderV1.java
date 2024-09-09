package com.github.justincranford.springs.util.security.hashes.encoder.pepper;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Function;

import com.github.justincranford.springs.util.basic.StringUtil;
import com.github.justincranford.springs.util.security.hashes.encoder.EncodeDecode;
import com.github.justincranford.springs.util.security.hashes.encoder.model.HashConstantParameters;
import com.github.justincranford.springs.util.security.hashes.encoder.model.HashConstantParametersAndHashPeppers;
import com.github.justincranford.springs.util.security.hashes.encoder.model.HashConstantParametersAndHashVariableParameters;
import com.github.justincranford.springs.util.security.hashes.encoder.model.HashConstantParametersAndHashVariableParametersAndHash;
import com.github.justincranford.springs.util.security.hashes.encoder.model.HashPeppers;
import com.github.justincranford.springs.util.security.hashes.encoder.model.HashVariableParameters;
import com.github.justincranford.springs.util.security.hashes.encoder.IocEncoder;
import com.github.justincranford.springs.util.security.hashes.encoder.model.Pepper;

import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Null;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@SuppressWarnings({"nls"})
public abstract class PepperedHashEncoderV1 extends IocEncoder {
	public PepperedHashEncoderV1(
		@NotNull final HashConstantParametersAndHashPeppers hashConstantParametersAndPeppersForHash,
		@NotNull final Function<CharSequence, byte[]>       hashSaltSupplier
	) {
		final HashConstantParameters hashConstantParameters = hashConstantParametersAndPeppersForHash.hashConstantParameters();
		final HashPeppers            hashPeppers            = hashConstantParametersAndPeppersForHash.hashPeppers();
		super.encode = (rawInput) -> {
			final HashVariableParameters                          hashVariableParameters                          = new HashVariableParameters(hashSaltSupplier.apply(rawInput));
			final HashConstantParametersAndHashVariableParameters hashConstantParametersAndHashVariableParameters = new HashConstantParametersAndHashVariableParameters(hashConstantParameters, hashVariableParameters);
			final byte[]                                          hashBytes                                       = computeHash(rawInput, hashConstantParametersAndHashVariableParameters, hashPeppers);
			return encodeHashConstantParametersAndHashVariableParametersAndHash(hashConstantParametersAndHashVariableParameters, hashBytes);
		};
		super.matches = (rawInput, encodedHashConstantParametersAndHashVariableParametersAndHash) -> {
			final HashVariableParameters                                 hashVariableParameters                                        = new HashVariableParameters(hashSaltSupplier.apply(rawInput));
			final HashConstantParametersAndHashVariableParametersAndHash hashConstantParametersAndHashVariableParametersAndHashDecoded = decodeHashConstantParametersAndHashVariableParametersAndHash(encodedHashConstantParametersAndHashVariableParametersAndHash, hashConstantParameters, hashVariableParameters);
			final byte[]                                                 hashBytes                                                     = computeHash(rawInput, hashConstantParametersAndHashVariableParametersAndHashDecoded.hashConstantParametersAndHashVariableParameters(), hashPeppers);
			return Boolean.valueOf(MessageDigest.isEqual(hashBytes, hashConstantParametersAndHashVariableParametersAndHashDecoded.hashBytes()));
		};
		super.upgradeEncoding = (encodedHashConstantParametersAndHashVariableParametersAndHash) -> {
			if (encodedHashConstantParametersAndHashVariableParametersAndHash == null || encodedHashConstantParametersAndHashVariableParametersAndHash.length() == 0) {
				return Boolean.FALSE;
			}
			final int                                                    hashBytesLength                                               = hashSaltSupplier.apply("").length;
			final HashVariableParameters                                 hashVariableParameters                                        = new HashVariableParameters(new byte[hashBytesLength]);
			final HashConstantParametersAndHashVariableParametersAndHash hashConstantParametersAndHashVariableParametersAndHashDecoded = decodeHashConstantParametersAndHashVariableParametersAndHash(encodedHashConstantParametersAndHashVariableParametersAndHash, hashConstantParameters, hashVariableParameters);
			final HashConstantParametersAndHashVariableParameters        hashConstantParametersAndHashVariableParametersDecoded        = hashConstantParametersAndHashVariableParametersAndHashDecoded.hashConstantParametersAndHashVariableParameters();
			final HashConstantParameters                                 hashConstantParametersDecoded                                 = hashConstantParametersAndHashVariableParametersDecoded.hashConstantParameters();
			final HashVariableParameters                                 hashVariableParametersDecoded                                 = hashConstantParametersAndHashVariableParametersDecoded.hashVariableParameters();
			final byte[]                                                 hashSaltBytesDecoded                                          = hashVariableParametersDecoded.hashSaltBytes();
			final byte[]                                                 pepperedHashBytes                                             = hashConstantParametersAndHashVariableParametersAndHashDecoded.hashBytes();
			final byte[]                                                 pepperedHashDecodedBytes                                      = optionalDecodePepper(hashPeppers.hashPostHashPepper().pepper(), pepperedHashBytes);
			return hashConstantParameters.recompute(hashBytesLength, hashSaltBytesDecoded.length, hashConstantParametersDecoded, pepperedHashDecodedBytes.length);
		};
	}

	private static byte[] computeHash(final CharSequence rawInput, final HashConstantParametersAndHashVariableParameters hashConstantParametersAndHashVariableParameters, final HashPeppers peppersForHash) {
		final HashConstantParameters hashConstantParameters = hashConstantParametersAndHashVariableParameters.hashConstantParameters();
		final byte[]                 plainSaltBytes         = hashConstantParametersAndHashVariableParameters.hashVariableParameters().hashSaltBytes();
		final byte[]                 additionalDataBytes    = hashConstantParametersAndHashVariableParameters.canonicalBytes();
		final byte[]                 pepperedSaltBytes      = optionalPepperAndEncode(peppersForHash.hashSaltPepper().pepper(), plainSaltBytes, additionalDataBytes); // pre-salt step
		final byte[]                 plainInputBytes        = rawInput.toString().getBytes(StandardCharsets.UTF_8);
		final byte[]                 pepperedInputBytes     = optionalPepperAndEncode(peppersForHash.hashPreHashPepper().pepper(), plainInputBytes, additionalDataBytes); // pre-hash step
		final String                 pepperedInputString    = new String(pepperedInputBytes, StandardCharsets.UTF_8);
		final byte[]                 plainHashBytes         = computeHash(hashConstantParameters, pepperedSaltBytes, pepperedInputString);
		final byte[]                 pepperedHashBytes      = optionalPepperAndEncode(peppersForHash.hashPostHashPepper().pepper(), plainHashBytes, additionalDataBytes); // post-hash step (aka pepper)
		return pepperedHashBytes;
	}

	private static byte[] optionalPepperAndEncode(@Null final Pepper pepper, @NotEmpty final byte[] bytes, @NotNull final byte[] additionalData) {
		return (pepper == null) ? bytes : pepper.compute(bytes, additionalData);
	}
	private static byte[] optionalDecodePepper(@Null final Pepper pepper, @NotNull final byte[] pepperedHashBytes) {
		return (pepper == null) ? pepperedHashBytes : pepper.encoderDecoder().decodeFromBytes(pepperedHashBytes);
	}

	private static byte[] computeHash(@NotNull final HashConstantParameters hashConstantParameters, @NotNull final byte[] hashSaltBytes, @NotNull final CharSequence rawInput) {
		return hashConstantParameters.compute(hashSaltBytes, rawInput);
	}

	private static String encodeHashConstantParametersAndHashVariableParametersAndHash(@NotNull final HashConstantParametersAndHashVariableParameters hashConstantParametersAndHashVariableParameters, @NotEmpty final byte[] hashBytes) {
		final String encodedHashConstantParametersAndHashVariableParameters = encodeHashConstantParametersAndHashVariableParameters(hashConstantParametersAndHashVariableParameters);
		final String encodedHash                      = encodeHash(hashConstantParametersAndHashVariableParameters.hashConstantParameters(), hashBytes);
		if (encodedHashConstantParametersAndHashVariableParameters.isEmpty()) {
			return encodedHash;
		}
		return encodedHashConstantParametersAndHashVariableParameters + hashConstantParametersAndHashVariableParameters.hashConstantParameters().encodeDecode().separators().parametersVsHash() + encodedHash;
	}
	public static HashConstantParametersAndHashVariableParametersAndHash decodeHashConstantParametersAndHashVariableParametersAndHash(@NotNull final String hashConstantParametersAndHashVariableParametersAndHash, @NotNull final HashConstantParameters defaultHashConstantParameters, @NotNull HashVariableParameters hashVariableParameters) {
	    final List<String> parts = StringUtil.split(hashConstantParametersAndHashVariableParametersAndHash, defaultHashConstantParameters.encodeDecode().separators().parametersVsHash());
	    final byte[] hashSaltBytes = hashVariableParameters.hashSaltBytes();
		final HashConstantParametersAndHashVariableParameters hashConstantParametersAndHashVariableParameters = decodeHashConstantParametersAndHashVariableParameters((parts.size() == 1) ? "" : parts.removeFirst(), defaultHashConstantParameters, hashSaltBytes);
		final byte[] hashBytes = decodeHash(defaultHashConstantParameters, parts.removeFirst());
		if (parts.isEmpty()) {
			return new HashConstantParametersAndHashVariableParametersAndHash(hashConstantParametersAndHashVariableParameters, hashBytes);
		}
		throw new RuntimeException("Leftover parts");
	}
	private static String encodeHashConstantParametersAndHashVariableParameters(@NotNull final HashConstantParametersAndHashVariableParameters hashConstantParametersAndHashVariableParameters) {
		final HashConstantParameters hashConstantParameters            = hashConstantParametersAndHashVariableParameters.hashConstantParameters();
		final List<Object>           hashConstantParametersToBeEncoded = new ArrayList<>();
		final EncodeDecode           encodeDecode                      = hashConstantParameters.encodeDecode();
		if (encodeDecode.flags().hashSalt()) {
			hashConstantParametersToBeEncoded.add(encodeDecode.encoderDecoder().encodeToString(hashConstantParametersAndHashVariableParameters.hashVariableParameters().hashSaltBytes()));
		}
		if (encodeDecode.flags().hashConstantParameters()) {
			hashConstantParametersToBeEncoded.addAll(hashConstantParameters.canonicalObjects());
		}
		return StringUtil.toString("", encodeDecode.separators().intraParameters(), "", hashConstantParametersToBeEncoded);
	}

	private static HashConstantParametersAndHashVariableParameters decodeHashConstantParametersAndHashVariableParameters(final String encodedParameters, @NotNull final HashConstantParameters defaultHashConstantParameters, @NotNull final byte[] hashSaltBytes) {
		final EncodeDecode             encodeDecode                  = defaultHashConstantParameters.encodeDecode();
		final List<String>             parts                         = StringUtil.split(encodedParameters, encodeDecode.separators().intraParameters());
		final byte[]                   hashSaltBytesDecoded          = (encodeDecode.flags().hashSalt())  ? encodeDecode.encoderDecoder().decodeFromString(parts.removeFirst()) : hashSaltBytes;
		final HashVariableParameters   hashVariableParametersDecoded = new HashVariableParameters(hashSaltBytesDecoded);
		final HashConstantParameters   hashConstantParametersDecoded = defaultHashConstantParameters.decode(parts, encodeDecode);
		if (parts.isEmpty()) {
			return new HashConstantParametersAndHashVariableParameters(hashConstantParametersDecoded, hashVariableParametersDecoded);
		}
		throw new RuntimeException("Leftover parts");
	}

	private static String encodeHash(@NotNull final HashConstantParameters hashConstantParameters, @NotEmpty final byte[] hash) {
		return hashConstantParameters.encodeDecode().encoderDecoder().encodeToString(hash);
	}
	private static byte[] decodeHash(@NotNull final HashConstantParameters hashConstantParameters, @NotEmpty final String encodedHash) {
		return hashConstantParameters.encodeDecode().encoderDecoder().decodeFromString(encodedHash);
	}
}
