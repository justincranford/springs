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
import com.github.justincranford.springs.util.security.hashes.encoder.model.HashConstantParametersAndHashSalt;
import com.github.justincranford.springs.util.security.hashes.encoder.model.HashConstantParametersAndHashSaltAndHash;
import com.github.justincranford.springs.util.security.hashes.encoder.model.HashPeppers;
import com.github.justincranford.springs.util.security.hashes.encoder.IocEncoder;
import com.github.justincranford.springs.util.security.hashes.encoder.model.Pepper;

import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Null;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@SuppressWarnings({"nls"})
public abstract class PepperedCipherEncoderV1 extends IocEncoder {
	public PepperedCipherEncoderV1(
		@NotNull final HashConstantParametersAndHashPeppers hashConstantParametersAndPeppersForHash,
		@NotNull final Function<CharSequence, byte[]> hashSaltSupplier
	) {
		final HashConstantParameters hashConstantParameters = hashConstantParametersAndPeppersForHash.hashConstantParameters();
		final HashPeppers    hashPeppers    = hashConstantParametersAndPeppersForHash.peppersForMacs();
		super.encode = (rawInput) -> {
			final byte[]                    hashSaltBytes             = hashSaltSupplier.apply(rawInput);
			final HashConstantParametersAndHashSalt hashConstantParametersAndHashSalt = new HashConstantParametersAndHashSalt(hashConstantParameters, hashSaltBytes);
			final byte[]                    hashBytes                 = computeHash(rawInput, hashConstantParametersAndHashSalt, hashPeppers);
			return encodeHashConstantParametersAndHashSaltAndHash(hashConstantParametersAndHashSalt, hashBytes);
		};
		super.matches = (rawInput, encodedHashConstantParametersAndHashSaltAndHash) -> {
			final byte[]                           hashSaltBytes                    = hashSaltSupplier.apply(rawInput);
			final HashConstantParametersAndHashSaltAndHash hashConstantParametersAndHashSaltAndHash = decodeHashConstantParametersAndHashSaltAndHash(encodedHashConstantParametersAndHashSaltAndHash, hashConstantParameters, hashSaltBytes);
			final byte[]                           hashBytes                        = computeHash(rawInput, hashConstantParametersAndHashSaltAndHash.hashConstantParametersAndHashSalt(), hashPeppers);
			return Boolean.valueOf(MessageDigest.isEqual(hashBytes, hashConstantParametersAndHashSaltAndHash.hashBytes()));
		};
		super.upgradeEncoding = (encodedHashConstantParametersAndHashSaltAndHash) -> {
			if (encodedHashConstantParametersAndHashSaltAndHash == null || encodedHashConstantParametersAndHashSaltAndHash.length() == 0) {
				return Boolean.FALSE;
			}
			final byte[]                           hashSaltBytes                    = hashSaltSupplier.apply(""); // value not used, only its length
			final HashConstantParametersAndHashSaltAndHash hashConstantParametersAndHashSaltAndHash = decodeHashConstantParametersAndHashSaltAndHash(encodedHashConstantParametersAndHashSaltAndHash, hashConstantParameters, hashSaltBytes);
			final HashConstantParametersAndHashSalt        hashConstantParametersAndSaltDecoded     = hashConstantParametersAndHashSaltAndHash.hashConstantParametersAndHashSalt();
			final HashConstantParameters                   hashConstantParametersDecoded            = hashConstantParametersAndSaltDecoded.hashConstantParameters();
			final byte[]                           hashSaltBytesDecoded             = hashConstantParametersAndSaltDecoded.hashSaltBytes();
			final byte[]                           pepperedHashBytes                = hashConstantParametersAndHashSaltAndHash.hashBytes();
			final byte[]                           pepperedHashDecodedBytes         = optionalDecodePepper(hashPeppers.hashPostHashPepper().pepper(), pepperedHashBytes);
			return hashConstantParameters.recompute(hashSaltBytes.length, hashSaltBytesDecoded.length, hashConstantParametersDecoded, pepperedHashDecodedBytes.length);
		};
	}

	private static byte[] computeHash(final CharSequence rawInput, final HashConstantParametersAndHashSalt hashConstantParametersAndHashSalt, final HashPeppers peppersForHash) {
		final HashConstantParameters hashConstantParameters      = hashConstantParametersAndHashSalt.hashConstantParameters();
		final byte[]         plainSaltBytes      = hashConstantParametersAndHashSalt.hashSaltBytes();
		final byte[]         additionalDataBytes = hashConstantParametersAndHashSalt.canonicalBytes();
		final byte[]         pepperedSaltBytes   = optionalPepperAndEncode(peppersForHash.hashSaltPepper().pepper(), plainSaltBytes, additionalDataBytes); // pre-salt step
		final byte[]         plainInputBytes     = rawInput.toString().getBytes(StandardCharsets.UTF_8);
		final byte[]         pepperedInputBytes  = optionalPepperAndEncode(peppersForHash.hashPreHashPepper().pepper(), plainInputBytes, additionalDataBytes); // pre-hash step
		final String         pepperedInputString = new String(pepperedInputBytes, StandardCharsets.UTF_8);
		final byte[]         plainHashBytes      = computeHash(hashConstantParameters, pepperedSaltBytes, pepperedInputString);
		final byte[]         pepperedHashBytes   = optionalPepperAndEncode(peppersForHash.hashPostHashPepper().pepper(), plainHashBytes, additionalDataBytes); // post-hash step (aka pepper)
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

	private static String encodeHashConstantParametersAndHashSaltAndHash(@NotNull final HashConstantParametersAndHashSalt hashConstantParametersAndHashSalt, @NotEmpty final byte[] hashBytes) {
		final String encodedHashConstantParametersAndHashSalt = encodeHashConstantParametersAndHashSalt(hashConstantParametersAndHashSalt);
		final String encodedHash                      = encodeHash(hashConstantParametersAndHashSalt.hashConstantParameters(), hashBytes);
		if (encodedHashConstantParametersAndHashSalt.isEmpty()) {
			return encodedHash;
		}
		return encodedHashConstantParametersAndHashSalt + hashConstantParametersAndHashSalt.hashConstantParameters().encodeDecode().separators().parametersVsHash() + encodedHash;
	}
	public static HashConstantParametersAndHashSaltAndHash decodeHashConstantParametersAndHashSaltAndHash(@NotNull final String hashConstantParametersAndHashSaltAndHash, @NotNull final HashConstantParameters defaultHashConstantParameters, @NotNull final byte[] hashSaltBytes) {
	    final List<String> parts = StringUtil.split(hashConstantParametersAndHashSaltAndHash, defaultHashConstantParameters.encodeDecode().separators().parametersVsHash());
		final HashConstantParametersAndHashSalt hashConstantParametersAndHashSalt = decodeHashConstantParametersAndHashSalt((parts.size() == 1) ? "" : parts.removeFirst(), defaultHashConstantParameters, hashSaltBytes);
		final byte[] hashBytes = decodeHash(defaultHashConstantParameters, parts.removeFirst());
		if (parts.isEmpty()) {
			return new HashConstantParametersAndHashSaltAndHash(hashConstantParametersAndHashSalt, hashBytes);
		}
		throw new RuntimeException("Leftover parts");
	}
	private static String encodeHashConstantParametersAndHashSalt(@NotNull final HashConstantParametersAndHashSalt hashConstantParametersAndHashSalt) {
		final HashConstantParameters   hashConstantParameters            = hashConstantParametersAndHashSalt.hashConstantParameters();
		final List<Object>     hashConstantParametersToBeEncoded = new ArrayList<>();
		final EncodeDecode encodeDecode          = hashConstantParameters.encodeDecode();
		if (encodeDecode.flags().hashSalt()) {
			hashConstantParametersToBeEncoded.add(encodeDecode.encoderDecoder().encodeToString(hashConstantParametersAndHashSalt.hashSaltBytes()));
		}
		if (encodeDecode.flags().hashConstantParameters()) {
			hashConstantParametersToBeEncoded.addAll(hashConstantParameters.canonicalObjects());
		}
		return StringUtil.toString("", encodeDecode.separators().intraParameters(), "", hashConstantParametersToBeEncoded);
	}

	private static HashConstantParametersAndHashSalt decodeHashConstantParametersAndHashSalt(final String encodedParameters, @NotNull final HashConstantParameters defaultHashConstantParameters, @NotNull final byte[] hashSaltBytes) {
		final EncodeDecode encodeDecode      = defaultHashConstantParameters.encodeDecode();
		final List<String>     parts                 = StringUtil.split(encodedParameters, encodeDecode.separators().intraParameters());
		final byte[]           hashSaltBytesDecoded  = (encodeDecode.flags().hashSalt())  ? encodeDecode.encoderDecoder().decodeFromString(parts.removeFirst()) : hashSaltBytes;
		final HashConstantParameters   hashConstantParametersDecoded = defaultHashConstantParameters.decode(parts, encodeDecode);
		if (parts.isEmpty()) {
			return new HashConstantParametersAndHashSalt(hashConstantParametersDecoded, hashSaltBytesDecoded);
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
