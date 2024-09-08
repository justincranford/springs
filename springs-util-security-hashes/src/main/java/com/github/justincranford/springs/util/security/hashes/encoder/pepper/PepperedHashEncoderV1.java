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
public abstract class PepperedHashEncoderV1 extends IocEncoder {
	public PepperedHashEncoderV1(
		@NotNull final HashConstantParametersAndHashPeppers hashParametersAndPeppersForHash,
		@NotNull final Function<CharSequence, byte[]> hashSaltSupplier
	) {
		final HashConstantParameters hashParameters = hashParametersAndPeppersForHash.hashParameters();
		final HashPeppers    hashPeppers    = hashParametersAndPeppersForHash.peppersForMacs();
		super.encode = (rawInput) -> {
			final byte[]                    hashSaltBytes             = hashSaltSupplier.apply(rawInput);
			final HashConstantParametersAndHashSalt hashParametersAndHashSalt = new HashConstantParametersAndHashSalt(hashParameters, hashSaltBytes);
			final byte[]                    hashBytes                 = computeHash(rawInput, hashParametersAndHashSalt, hashPeppers);
			return encodeHashParametersAndHashSaltAndHash(hashParametersAndHashSalt, hashBytes);
		};
		super.matches = (rawInput, encodedHashParametersAndHashSaltAndHash) -> {
			final byte[]                           hashSaltBytes                    = hashSaltSupplier.apply(rawInput);
			final HashConstantParametersAndHashSaltAndHash hashParametersAndHashSaltAndHash = decodeHashParametersAndHashSaltAndHash(encodedHashParametersAndHashSaltAndHash, hashParameters, hashSaltBytes);
			final byte[]                           hashBytes                        = computeHash(rawInput, hashParametersAndHashSaltAndHash.hashParametersAndHashSalt(), hashPeppers);
			return Boolean.valueOf(MessageDigest.isEqual(hashBytes, hashParametersAndHashSaltAndHash.hashBytes()));
		};
		super.upgradeEncoding = (encodedHashParametersAndHashSaltAndHash) -> {
			if (encodedHashParametersAndHashSaltAndHash == null || encodedHashParametersAndHashSaltAndHash.length() == 0) {
				return Boolean.FALSE;
			}
			final byte[]                           hashSaltBytes                    = hashSaltSupplier.apply(""); // value not used, only its length
			final HashConstantParametersAndHashSaltAndHash hashParametersAndHashSaltAndHash = decodeHashParametersAndHashSaltAndHash(encodedHashParametersAndHashSaltAndHash, hashParameters, hashSaltBytes);
			final HashConstantParametersAndHashSalt        hashParametersAndSaltDecoded     = hashParametersAndHashSaltAndHash.hashParametersAndHashSalt();
			final HashConstantParameters                   hashParametersDecoded            = hashParametersAndSaltDecoded.hashParameters();
			final byte[]                           hashSaltBytesDecoded             = hashParametersAndSaltDecoded.hashSaltBytes();
			final byte[]                           pepperedHashBytes                = hashParametersAndHashSaltAndHash.hashBytes();
			final byte[]                           pepperedHashDecodedBytes         = optionalDecodePepper(hashPeppers.hashPostHashPepper().pepper(), pepperedHashBytes);
			return hashParameters.recompute(hashSaltBytes.length, hashSaltBytesDecoded.length, hashParametersDecoded, pepperedHashDecodedBytes.length);
		};
	}

	private static byte[] computeHash(final CharSequence rawInput, final HashConstantParametersAndHashSalt hashParametersAndHashSalt, final HashPeppers peppersForHash) {
		final HashConstantParameters hashParameters      = hashParametersAndHashSalt.hashParameters();
		final byte[]         plainSaltBytes      = hashParametersAndHashSalt.hashSaltBytes();
		final byte[]         additionalDataBytes = hashParametersAndHashSalt.canonicalBytes();
		final byte[]         pepperedSaltBytes   = optionalPepperAndEncode(peppersForHash.hashSaltPepper().pepper(), plainSaltBytes, additionalDataBytes); // pre-salt step
		final byte[]         plainInputBytes     = rawInput.toString().getBytes(StandardCharsets.UTF_8);
		final byte[]         pepperedInputBytes  = optionalPepperAndEncode(peppersForHash.hashPreHashPepper().pepper(), plainInputBytes, additionalDataBytes); // pre-hash step
		final String         pepperedInputString = new String(pepperedInputBytes, StandardCharsets.UTF_8);
		final byte[]         plainHashBytes      = computeHash(hashParameters, pepperedSaltBytes, pepperedInputString);
		final byte[]         pepperedHashBytes   = optionalPepperAndEncode(peppersForHash.hashPostHashPepper().pepper(), plainHashBytes, additionalDataBytes); // post-hash step (aka pepper)
		return pepperedHashBytes;
	}

	private static byte[] optionalPepperAndEncode(@Null final Pepper pepper, @NotEmpty final byte[] bytes, @NotNull final byte[] additionalData) {
		return (pepper == null) ? bytes : pepper.compute(bytes, additionalData);
	}
	private static byte[] optionalDecodePepper(@Null final Pepper pepper, @NotNull final byte[] pepperedHashBytes) {
		return (pepper == null) ? pepperedHashBytes : pepper.encoderDecoder().decodeFromBytes(pepperedHashBytes);
	}

	private static byte[] computeHash(@NotNull final HashConstantParameters hashParameters, @NotNull final byte[] hashSaltBytes, @NotNull final CharSequence rawInput) {
		return hashParameters.compute(hashSaltBytes, rawInput);
	}

	private static String encodeHashParametersAndHashSaltAndHash(@NotNull final HashConstantParametersAndHashSalt hashParametersAndHashSalt, @NotEmpty final byte[] hashBytes) {
		final String encodedHashParametersAndHashSalt = encodeHashParametersAndHashSalt(hashParametersAndHashSalt);
		final String encodedHash                      = encodeHash(hashParametersAndHashSalt.hashParameters(), hashBytes);
		if (encodedHashParametersAndHashSalt.isEmpty()) {
			return encodedHash;
		}
		return encodedHashParametersAndHashSalt + hashParametersAndHashSalt.hashParameters().encodeDecode().separators().parametersVsHash() + encodedHash;
	}
	public static HashConstantParametersAndHashSaltAndHash decodeHashParametersAndHashSaltAndHash(@NotNull final String hashParametersAndHashSaltAndHash, @NotNull final HashConstantParameters defaultHashParameters, @NotNull final byte[] hashSaltBytes) {
	    final List<String> parts = StringUtil.split(hashParametersAndHashSaltAndHash, defaultHashParameters.encodeDecode().separators().parametersVsHash());
		final HashConstantParametersAndHashSalt hashParametersAndHashSalt = decodeHashParametersAndHashSalt((parts.size() == 1) ? "" : parts.removeFirst(), defaultHashParameters, hashSaltBytes);
		final byte[] hashBytes = decodeHash(defaultHashParameters, parts.removeFirst());
		if (parts.isEmpty()) {
			return new HashConstantParametersAndHashSaltAndHash(hashParametersAndHashSalt, hashBytes);
		}
		throw new RuntimeException("Leftover parts");
	}
	private static String encodeHashParametersAndHashSalt(@NotNull final HashConstantParametersAndHashSalt hashParametersAndHashSalt) {
		final HashConstantParameters   hashParameters            = hashParametersAndHashSalt.hashParameters();
		final List<Object>     hashParametersToBeEncoded = new ArrayList<>();
		final EncodeDecode encodeDecode          = hashParameters.encodeDecode();
		if (encodeDecode.flags().hashSalt()) {
			hashParametersToBeEncoded.add(encodeDecode.encoderDecoder().encodeToString(hashParametersAndHashSalt.hashSaltBytes()));
		}
		if (encodeDecode.flags().hashParameters()) {
			hashParametersToBeEncoded.addAll(hashParameters.canonicalObjects());
		}
		return StringUtil.toString("", encodeDecode.separators().intraParameters(), "", hashParametersToBeEncoded);
	}

	private static HashConstantParametersAndHashSalt decodeHashParametersAndHashSalt(final String encodedParameters, @NotNull final HashConstantParameters defaultHashParameters, @NotNull final byte[] hashSaltBytes) {
		final EncodeDecode encodeDecode      = defaultHashParameters.encodeDecode();
		final List<String>     parts                 = StringUtil.split(encodedParameters, encodeDecode.separators().intraParameters());
		final byte[]           hashSaltBytesDecoded  = (encodeDecode.flags().hashSalt())  ? encodeDecode.encoderDecoder().decodeFromString(parts.removeFirst()) : hashSaltBytes;
		final HashConstantParameters   hashParametersDecoded = defaultHashParameters.decode(parts, encodeDecode);
		if (parts.isEmpty()) {
			return new HashConstantParametersAndHashSalt(hashParametersDecoded, hashSaltBytesDecoded);
		}
		throw new RuntimeException("Leftover parts");
	}

	private static String encodeHash(@NotNull final HashConstantParameters hashParameters, @NotEmpty final byte[] hash) {
		return hashParameters.encodeDecode().encoderDecoder().encodeToString(hash);
	}
	private static byte[] decodeHash(@NotNull final HashConstantParameters hashParameters, @NotEmpty final String encodedHash) {
		return hashParameters.encodeDecode().encoderDecoder().decodeFromString(encodedHash);
	}
}
