package com.github.justincranford.springs.util.security.hashes.encoder.pepper;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Function;

import com.github.justincranford.springs.util.basic.StringUtil;
import com.github.justincranford.springs.util.security.hashes.encoder.EncodeDecode;
import com.github.justincranford.springs.util.security.hashes.encoder.model.HashParameters;
import com.github.justincranford.springs.util.security.hashes.encoder.model.HashParametersAndHashPeppers;
import com.github.justincranford.springs.util.security.hashes.encoder.model.HashParametersAndHashSalt;
import com.github.justincranford.springs.util.security.hashes.encoder.model.HashParametersAndHashSaltAndHash;
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
		@NotNull final HashParametersAndHashPeppers hashParametersAndPeppersForHash,
		@NotNull final Function<CharSequence, byte[]> hashSaltSupplier
	) {
		final HashParameters hashParameters = hashParametersAndPeppersForHash.hashParameters();
		final HashPeppers    hashPeppers    = hashParametersAndPeppersForHash.peppersForMacs();
		super.encode = (rawInput) -> {
			final byte[]                    hashSaltBytes             = hashSaltSupplier.apply(rawInput);
			final HashParametersAndHashSalt hashParametersAndHashSalt = new HashParametersAndHashSalt(hashParameters, hashSaltBytes);
			final byte[]                    hashBytes                 = computeHash(rawInput, hashParametersAndHashSalt, hashPeppers);
			return encodeHashParametersAndHashSaltAndHash(hashParametersAndHashSalt, hashBytes);
		};
		super.matches = (rawInput, encodedHashParametersAndHashSaltAndHash) -> {
			final byte[]                           hashSaltBytes                    = hashSaltSupplier.apply(rawInput);
			final HashParametersAndHashSaltAndHash hashParametersAndHashSaltAndHash = decodeHashParametersAndHashSaltAndHash(encodedHashParametersAndHashSaltAndHash, hashParameters, hashSaltBytes);
			final byte[]                           hashBytes                        = computeHash(rawInput, hashParametersAndHashSaltAndHash.hashParametersAndHashSalt(), hashPeppers);
			return Boolean.valueOf(MessageDigest.isEqual(hashBytes, hashParametersAndHashSaltAndHash.hashBytes()));
		};
		super.upgradeEncoding = (encodedHashParametersAndHashSaltAndHash) -> {
			if (encodedHashParametersAndHashSaltAndHash == null || encodedHashParametersAndHashSaltAndHash.length() == 0) {
				return Boolean.FALSE;
			}
			final byte[]                           hashSaltBytes                    = hashSaltSupplier.apply(""); // value not used, only its length
			final HashParametersAndHashSaltAndHash hashParametersAndHashSaltAndHash = decodeHashParametersAndHashSaltAndHash(encodedHashParametersAndHashSaltAndHash, hashParameters, hashSaltBytes);
			final HashParametersAndHashSalt        hashParametersAndSaltDecoded     = hashParametersAndHashSaltAndHash.hashParametersAndHashSalt();
			final HashParameters                   hashParametersDecoded            = hashParametersAndSaltDecoded.hashParameters();
			final byte[]                           hashSaltBytesDecoded             = hashParametersAndSaltDecoded.hashSaltBytes();
			final byte[]                           pepperedHashBytes                = hashParametersAndHashSaltAndHash.hashBytes();
			final byte[]                           pepperedHashDecodedBytes         = optionalDecodePepper(hashPeppers.hashPostHashPepper().pepper(), pepperedHashBytes);
			return hashParameters.recompute(hashSaltBytes.length, hashSaltBytesDecoded.length, hashParametersDecoded, pepperedHashDecodedBytes.length);
		};
	}

	private static byte[] computeHash(final CharSequence rawInput, final HashParametersAndHashSalt hashParametersAndHashSalt, final HashPeppers peppersForHash) {
		final HashParameters hashParameters      = hashParametersAndHashSalt.hashParameters();
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

	private static byte[] computeHash(@NotNull final HashParameters hashParameters, @NotNull final byte[] hashSaltBytes, @NotNull final CharSequence rawInput) {
		return hashParameters.compute(hashSaltBytes, rawInput);
	}

	private static String encodeHashParametersAndHashSaltAndHash(@NotNull final HashParametersAndHashSalt hashParametersAndHashSalt, @NotEmpty final byte[] hashBytes) {
		final String encodedHashParametersAndHashSalt = encodeHashParametersAndHashSalt(hashParametersAndHashSalt);
		final String encodedHash                      = encodeHash(hashParametersAndHashSalt.hashParameters(), hashBytes);
		if (encodedHashParametersAndHashSalt.isEmpty()) {
			return encodedHash;
		}
		return encodedHashParametersAndHashSalt + hashParametersAndHashSalt.hashParameters().encodeDecode().separators().parametersVsHash() + encodedHash;
	}
	public static HashParametersAndHashSaltAndHash decodeHashParametersAndHashSaltAndHash(@NotNull final String hashParametersAndHashSaltAndHash, @NotNull final HashParameters defaultHashParameters, @NotNull final byte[] hashSaltBytes) {
	    final List<String> parts = StringUtil.split(hashParametersAndHashSaltAndHash, defaultHashParameters.encodeDecode().separators().parametersVsHash());
		final HashParametersAndHashSalt hashParametersAndHashSalt = decodeHashParametersAndHashSalt((parts.size() == 1) ? "" : parts.removeFirst(), defaultHashParameters, hashSaltBytes);
		final byte[] hashBytes = decodeHash(defaultHashParameters, parts.removeFirst());
		if (parts.isEmpty()) {
			return new HashParametersAndHashSaltAndHash(hashParametersAndHashSalt, hashBytes);
		}
		throw new RuntimeException("Leftover parts");
	}
	private static String encodeHashParametersAndHashSalt(@NotNull final HashParametersAndHashSalt hashParametersAndHashSalt) {
		final HashParameters   hashParameters            = hashParametersAndHashSalt.hashParameters();
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

	private static HashParametersAndHashSalt decodeHashParametersAndHashSalt(final String encodedParameters, @NotNull final HashParameters defaultHashParameters, @NotNull final byte[] hashSaltBytes) {
		final EncodeDecode encodeDecode      = defaultHashParameters.encodeDecode();
		final List<String>     parts                 = StringUtil.split(encodedParameters, encodeDecode.separators().intraParameters());
		final byte[]           hashSaltBytesDecoded  = (encodeDecode.flags().hashSalt())  ? encodeDecode.encoderDecoder().decodeFromString(parts.removeFirst()) : hashSaltBytes;
		final HashParameters   hashParametersDecoded = defaultHashParameters.decode(parts, encodeDecode);
		if (parts.isEmpty()) {
			return new HashParametersAndHashSalt(hashParametersDecoded, hashSaltBytesDecoded);
		}
		throw new RuntimeException("Leftover parts");
	}

	private static String encodeHash(@NotNull final HashParameters hashParameters, @NotEmpty final byte[] hash) {
		return hashParameters.encodeDecode().encoderDecoder().encodeToString(hash);
	}
	private static byte[] decodeHash(@NotNull final HashParameters hashParameters, @NotEmpty final String encodedHash) {
		return hashParameters.encodeDecode().encoderDecoder().decodeFromString(encodedHash);
	}
}
