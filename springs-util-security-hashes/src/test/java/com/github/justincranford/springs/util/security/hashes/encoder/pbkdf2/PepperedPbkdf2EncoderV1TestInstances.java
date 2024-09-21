package com.github.justincranford.springs.util.security.hashes.encoder.pbkdf2;

import java.nio.charset.StandardCharsets;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import com.github.justincranford.springs.util.basic.Base64Util;
import com.github.justincranford.springs.util.basic.TextCodec;
import com.github.justincranford.springs.util.security.hashes.digest.DigestAlgorithm;
import com.github.justincranford.springs.util.security.hashes.encoder.HashCodec;
import com.github.justincranford.springs.util.security.hashes.encoder.HashCodec.Flags;
import com.github.justincranford.springs.util.security.hashes.encoder.model.HashInputConstantsAndHashPeppers;
import com.github.justincranford.springs.util.security.hashes.encoder.model.HashPepperPostHash;
import com.github.justincranford.springs.util.security.hashes.encoder.model.HashPepperPreHash;
import com.github.justincranford.springs.util.security.hashes.encoder.model.HashPepperInputVariables;
import com.github.justincranford.springs.util.security.hashes.encoder.model.HashPeppers;
import com.github.justincranford.springs.util.security.hashes.encoder.model.Pepper;
import com.github.justincranford.springs.util.security.hashes.encoder.pbkdf2.PepperedPbkdf2EncoderV1.ConstantSalt;
import com.github.justincranford.springs.util.security.hashes.encoder.pbkdf2.PepperedPbkdf2EncoderV1.DerivedSalt;
import com.github.justincranford.springs.util.security.hashes.encoder.pbkdf2.PepperedPbkdf2EncoderV1.RandomSalt;
import com.github.justincranford.springs.util.security.hashes.mac.MacAlgorithm;

import lombok.AccessLevel;
import lombok.NoArgsConstructor;

@SuppressWarnings({"nls"})
@NoArgsConstructor(access=AccessLevel.PRIVATE)
public final class PepperedPbkdf2EncoderV1TestInstances {
	public static final class Random {
		public static final RandomSalt SALTOTH_NULL_NULL_NULL       = new RandomSalt(ParametersAndPeppers.SALTOTH_NULL_NULL_NULL,       Defaults.RAND_LEN_BYTES);
		public static final RandomSalt SALTOTH_NONE_NONE_NONE       = new RandomSalt(ParametersAndPeppers.SALTOTH_NONE_NONE_NONE,       Defaults.RAND_LEN_BYTES);
		public static final RandomSalt SALTOTH_CTX_CTX_CTX          = new RandomSalt(ParametersAndPeppers.SALTOTH_CTX_CTX_CTX,          Defaults.RAND_LEN_BYTES);
		public static final RandomSalt SALTOTH_HSK_HSK_HSK          = new RandomSalt(ParametersAndPeppers.SALTOTH_HSK_HSK_HSK,          Defaults.RAND_LEN_BYTES);
		public static final RandomSalt SALTOTH_HSKCTX_HSKCTX_HSKCTX = new RandomSalt(ParametersAndPeppers.SALTOTH_HSKCTX_HSKCTX_HSKCTX, Defaults.RAND_LEN_BYTES);
		public static final RandomSalt SALTOTH_CSK_CSK_CSK          = new RandomSalt(ParametersAndPeppers.SALTOTH_CSK_CSK_CSK,          Defaults.RAND_LEN_BYTES);
		public static final RandomSalt SALTOTH_CSKCTX_CSKCTX_CSKCTX = new RandomSalt(ParametersAndPeppers.SALTOTH_CSKCTX_CSKCTX_CSKCTX, Defaults.RAND_LEN_BYTES);
		public static final RandomSalt SALT_NULL_NULL_NULL          = new RandomSalt(ParametersAndPeppers.SALT_NULL_NULL_NULL,          Defaults.RAND_LEN_BYTES);
		public static final RandomSalt SALT_NONE_NONE_NONE          = new RandomSalt(ParametersAndPeppers.SALT_NONE_NONE_NONE,          Defaults.RAND_LEN_BYTES);
		public static final RandomSalt SALT_CTX_CTX_CTX             = new RandomSalt(ParametersAndPeppers.SALT_CTX_CTX_CTX,             Defaults.RAND_LEN_BYTES);
		public static final RandomSalt SALT_HSK_HSK_HSK             = new RandomSalt(ParametersAndPeppers.SALT_HSK_HSK_HSK,             Defaults.RAND_LEN_BYTES);
		public static final RandomSalt SALT_HSKCTX_HSKCTX_HSKCTX    = new RandomSalt(ParametersAndPeppers.SALT_HSKCTX_HSKCTX_HSKCTX,    Defaults.RAND_LEN_BYTES);
		public static final RandomSalt SALT_CSK_CSK_CSK             = new RandomSalt(ParametersAndPeppers.SALT_CSK_CSK_CSK,             Defaults.RAND_LEN_BYTES);
		public static final RandomSalt SALT_CSKCTX_CSKCTX_CSKCTX    = new RandomSalt(ParametersAndPeppers.SALT_CSKCTX_CSKCTX_CSKCTX,    Defaults.RAND_LEN_BYTES);
	}

	public static final class Derived {
//		public static final DerivedSalt NONE_NULL_NULL_NULL       = new DerivedSalt(ParametersAndPeppers.NONE_NULL_NULL_NULL, Defaults.DER_LEN_BYTES);
		public static final DerivedSalt NONE_NONE_NONE_NONE       = new DerivedSalt(ParametersAndPeppers.NONE_NONE_NONE_NONE, Defaults.DER_LEN_BYTES);
		public static final DerivedSalt NONE_CTX_CTX_CTX          = new DerivedSalt(ParametersAndPeppers.NONE_CTX_CTX_CTX, Defaults.DER_LEN_BYTES);
		public static final DerivedSalt NONE_HSK_HSK_HSK          = new DerivedSalt(ParametersAndPeppers.NONE_HSK_HSK_HSK, Defaults.DER_LEN_BYTES);
		public static final DerivedSalt NONE_HSKCTX_HSKCTX_HSKCTX = new DerivedSalt(ParametersAndPeppers.NONE_HSKCTX_HSKCTX_HSKCTX, Defaults.DER_LEN_BYTES);
		public static final DerivedSalt NONE_CSK_CSK_CSK          = new DerivedSalt(ParametersAndPeppers.NONE_CSK_CSK_CSK, Defaults.DER_LEN_BYTES);
		public static final DerivedSalt NONE_CSKCTX_CSKCTX_CSKCTX = new DerivedSalt(ParametersAndPeppers.NONE_CSKCTX_CSKCTX_CSKCTX, Defaults.DER_LEN_BYTES);

//		public static final DerivedSalt SALT_NULL_NULL_NULL       = new DerivedSalt(ParametersAndPeppers.SALT_NULL_NULL_NULL, Defaults.DER_LEN_BYTES);
		public static final DerivedSalt SALT_NONE_NONE_NONE       = new DerivedSalt(ParametersAndPeppers.SALT_NONE_NONE_NONE, Defaults.DER_LEN_BYTES);
		public static final DerivedSalt SALT_CTX_CTX_CTX          = new DerivedSalt(ParametersAndPeppers.SALT_CTX_CTX_CTX, Defaults.DER_LEN_BYTES);
		public static final DerivedSalt SALT_HSK_HSK_HSK          = new DerivedSalt(ParametersAndPeppers.SALT_HSK_HSK_HSK, Defaults.DER_LEN_BYTES);
		public static final DerivedSalt SALT_HSKCTX_HSKCTX_HSKCTX = new DerivedSalt(ParametersAndPeppers.SALT_HSKCTX_HSKCTX_HSKCTX, Defaults.DER_LEN_BYTES);
		public static final DerivedSalt SALT_CSK_CSK_CSK          = new DerivedSalt(ParametersAndPeppers.SALT_CSK_CSK_CSK, Defaults.DER_LEN_BYTES);
		public static final DerivedSalt SALT_CSKCTX_CSKCTX_CSKCTX = new DerivedSalt(ParametersAndPeppers.SALT_CSKCTX_CSKCTX_CSKCTX, Defaults.DER_LEN_BYTES);

//		public static final DerivedSalt OTH_NULL_NULL_NULL       = new DerivedSalt(ParametersAndPeppers.OTH_NULL_NULL_NULL, Defaults.DER_LEN_BYTES);
		public static final DerivedSalt OTH_NONE_NONE_NONE       = new DerivedSalt(ParametersAndPeppers.OTH_NONE_NONE_NONE, Defaults.DER_LEN_BYTES);
		public static final DerivedSalt OTH_CTX_CTX_CTX          = new DerivedSalt(ParametersAndPeppers.OTH_CTX_CTX_CTX, Defaults.DER_LEN_BYTES);
		public static final DerivedSalt OTH_HSK_HSK_HSK          = new DerivedSalt(ParametersAndPeppers.OTH_HSK_HSK_HSK, Defaults.DER_LEN_BYTES);
		public static final DerivedSalt OTH_HSKCTX_HSKCTX_HSKCTX = new DerivedSalt(ParametersAndPeppers.OTH_HSKCTX_HSKCTX_HSKCTX, Defaults.DER_LEN_BYTES);
		public static final DerivedSalt OTH_CSK_CSK_CSK          = new DerivedSalt(ParametersAndPeppers.OTH_CSK_CSK_CSK, Defaults.DER_LEN_BYTES);
		public static final DerivedSalt OTH_CSKCTX_CSKCTX_CSKCTX = new DerivedSalt(ParametersAndPeppers.OTH_CSKCTX_CSKCTX_CSKCTX, Defaults.DER_LEN_BYTES);

//		public static final DerivedSalt SALTOTH_NULL_NULL_NULL       = new DerivedSalt(ParametersAndPeppers.SALTOTH_NULL_NULL_NULL, Defaults.DER_LEN_BYTES);
		public static final DerivedSalt SALTOTH_NONE_NONE_NONE       = new DerivedSalt(ParametersAndPeppers.SALTOTH_NONE_NONE_NONE, Defaults.DER_LEN_BYTES);
		public static final DerivedSalt SALTOTH_CTX_CTX_CTX          = new DerivedSalt(ParametersAndPeppers.SALTOTH_CTX_CTX_CTX, Defaults.DER_LEN_BYTES);
		public static final DerivedSalt SALTOTH_HSK_HSK_HSK          = new DerivedSalt(ParametersAndPeppers.SALTOTH_HSK_HSK_HSK, Defaults.DER_LEN_BYTES);
		public static final DerivedSalt SALTOTH_HSKCTX_HSKCTX_HSKCTX = new DerivedSalt(ParametersAndPeppers.SALTOTH_HSKCTX_HSKCTX_HSKCTX, Defaults.DER_LEN_BYTES);
		public static final DerivedSalt SALTOTH_CSK_CSK_CSK          = new DerivedSalt(ParametersAndPeppers.SALTOTH_CSK_CSK_CSK, Defaults.DER_LEN_BYTES);
		public static final DerivedSalt SALTOTH_CSKCTX_CSKCTX_CSKCTX = new DerivedSalt(ParametersAndPeppers.SALTOTH_CSKCTX_CSKCTX_CSKCTX, Defaults.DER_LEN_BYTES);
	}

	public static final class Constant {
		public static final ConstantSalt NONE_NULL_NULL_NULL       = new ConstantSalt(ParametersAndPeppers.NONE_NULL_NULL_NULL, Defaults.CONST_BYTES);
		public static final ConstantSalt NONE_NONE_NONE_NONE       = new ConstantSalt(ParametersAndPeppers.NONE_NONE_NONE_NONE, Defaults.CONST_BYTES);
		public static final ConstantSalt NONE_CTX_CTX_CTX          = new ConstantSalt(ParametersAndPeppers.NONE_CTX_CTX_CTX, Defaults.CONST_BYTES);
		public static final ConstantSalt NONE_HSK_HSK_HSK          = new ConstantSalt(ParametersAndPeppers.NONE_HSK_HSK_HSK, Defaults.CONST_BYTES);
		public static final ConstantSalt NONE_HSKCTX_HSKCTX_HSKCTX = new ConstantSalt(ParametersAndPeppers.NONE_HSKCTX_HSKCTX_HSKCTX, Defaults.CONST_BYTES);
		public static final ConstantSalt NONE_CSK_CSK_CSK          = new ConstantSalt(ParametersAndPeppers.NONE_CSK_CSK_CSK, Defaults.CONST_BYTES);
		public static final ConstantSalt NONE_CSKCTX_CSKCTX_CSKCTX = new ConstantSalt(ParametersAndPeppers.NONE_CSKCTX_CSKCTX_CSKCTX, Defaults.CONST_BYTES);

		public static final ConstantSalt SALT_NULL_NULL_NULL       = new ConstantSalt(ParametersAndPeppers.SALT_NULL_NULL_NULL, Defaults.CONST_BYTES);
		public static final ConstantSalt SALT_NONE_NONE_NONE       = new ConstantSalt(ParametersAndPeppers.SALT_NONE_NONE_NONE, Defaults.CONST_BYTES);
		public static final ConstantSalt SALT_CTX_CTX_CTX          = new ConstantSalt(ParametersAndPeppers.SALT_CTX_CTX_CTX, Defaults.CONST_BYTES);
		public static final ConstantSalt SALT_HSK_HSK_HSK          = new ConstantSalt(ParametersAndPeppers.SALT_HSK_HSK_HSK, Defaults.CONST_BYTES);
		public static final ConstantSalt SALT_HSKCTX_HSKCTX_HSKCTX = new ConstantSalt(ParametersAndPeppers.SALT_HSKCTX_HSKCTX_HSKCTX, Defaults.CONST_BYTES);
		public static final ConstantSalt SALT_CSK_CSK_CSK          = new ConstantSalt(ParametersAndPeppers.SALT_CSK_CSK_CSK, Defaults.CONST_BYTES);
		public static final ConstantSalt SALT_CSKCTX_CSKCTX_CSKCTX = new ConstantSalt(ParametersAndPeppers.SALT_CSKCTX_CSKCTX_CSKCTX, Defaults.CONST_BYTES);

		public static final ConstantSalt OTH_NULL_NULL_NULL       = new ConstantSalt(ParametersAndPeppers.OTH_NULL_NULL_NULL, Defaults.CONST_BYTES);
		public static final ConstantSalt OTH_NONE_NONE_NONE       = new ConstantSalt(ParametersAndPeppers.OTH_NONE_NONE_NONE, Defaults.CONST_BYTES);
		public static final ConstantSalt OTH_CTX_CTX_CTX          = new ConstantSalt(ParametersAndPeppers.OTH_CTX_CTX_CTX, Defaults.CONST_BYTES);
		public static final ConstantSalt OTH_HSK_HSK_HSK          = new ConstantSalt(ParametersAndPeppers.OTH_HSK_HSK_HSK, Defaults.CONST_BYTES);
		public static final ConstantSalt OTH_HSKCTX_HSKCTX_HSKCTX = new ConstantSalt(ParametersAndPeppers.OTH_HSKCTX_HSKCTX_HSKCTX, Defaults.CONST_BYTES);
		public static final ConstantSalt OTH_CSK_CSK_CSK          = new ConstantSalt(ParametersAndPeppers.OTH_CSK_CSK_CSK, Defaults.CONST_BYTES);
		public static final ConstantSalt OTH_CSKCTX_CSKCTX_CSKCTX = new ConstantSalt(ParametersAndPeppers.OTH_CSKCTX_CSKCTX_CSKCTX, Defaults.CONST_BYTES);

		public static final ConstantSalt SALTOTH_NULL_NULL_NULL       = new ConstantSalt(ParametersAndPeppers.SALTOTH_NULL_NULL_NULL, Defaults.CONST_BYTES);
		public static final ConstantSalt SALTOTH_NONE_NONE_NONE       = new ConstantSalt(ParametersAndPeppers.SALTOTH_NONE_NONE_NONE, Defaults.CONST_BYTES);
		public static final ConstantSalt SALTOTH_CTX_CTX_CTX          = new ConstantSalt(ParametersAndPeppers.SALTOTH_CTX_CTX_CTX, Defaults.CONST_BYTES);
		public static final ConstantSalt SALTOTH_HSK_HSK_HSK          = new ConstantSalt(ParametersAndPeppers.SALTOTH_HSK_HSK_HSK, Defaults.CONST_BYTES);
		public static final ConstantSalt SALTOTH_HSKCTX_HSKCTX_HSKCTX = new ConstantSalt(ParametersAndPeppers.SALTOTH_HSKCTX_HSKCTX_HSKCTX, Defaults.CONST_BYTES);
		public static final ConstantSalt SALTOTH_CSK_CSK_CSK          = new ConstantSalt(ParametersAndPeppers.SALTOTH_CSK_CSK_CSK, Defaults.CONST_BYTES);
		public static final ConstantSalt SALTOTH_CSKCTX_CSKCTX_CSKCTX = new ConstantSalt(ParametersAndPeppers.SALTOTH_CSKCTX_CSKCTX_CSKCTX, Defaults.CONST_BYTES);
	}

	public static class Defaults {
		public static final int ITER = 600_000;
		public static final int DK_BYTES_LEN = 32;
		public static final Pbkdf2AlgorithmV1 PRF_ALG = Pbkdf2AlgorithmV1.PBKDF2WithHmacSHA256;

		public static final int RAND_LEN_BYTES = 32;
		public static final int DER_LEN_BYTES = 32;
		public static final byte[] CONST_BYTES = "constant-salt-bytes".getBytes(StandardCharsets.UTF_8);

		public static final HashCodec B64_STD_CB_NONE     = new HashCodec(TextCodec.B64_STD, "|", ":", Flags.NONE);
		public static final HashCodec B64_STD_CB_SALT     = new HashCodec(TextCodec.B64_STD, "|", ":", Flags.VARS);
		public static final HashCodec B64_STD_CB_OTH      = new HashCodec(TextCodec.B64_STD, "|", ":", Flags.CONS);
		public static final HashCodec B64_STD_CB_SALT_OTH = new HashCodec(TextCodec.B64_STD, "|", ":", Flags.BOTH);
	}

	public static class Parameters {
		public static final Pbkdf2InputConstantsV1 STD_CB_NONE     = new Pbkdf2InputConstantsV1(Defaults.PRF_ALG, Defaults.ITER, Defaults.DK_BYTES_LEN, Defaults.B64_STD_CB_NONE);
		public static final Pbkdf2InputConstantsV1 STD_CB_SALT     = new Pbkdf2InputConstantsV1(Defaults.PRF_ALG, Defaults.ITER, Defaults.DK_BYTES_LEN, Defaults.B64_STD_CB_SALT);
		public static final Pbkdf2InputConstantsV1 STD_CB_OTH      = new Pbkdf2InputConstantsV1(Defaults.PRF_ALG, Defaults.ITER, Defaults.DK_BYTES_LEN, Defaults.B64_STD_CB_OTH);
		public static final Pbkdf2InputConstantsV1 STD_CB_SALT_OTH = new Pbkdf2InputConstantsV1(Defaults.PRF_ALG, Defaults.ITER, Defaults.DK_BYTES_LEN, Defaults.B64_STD_CB_SALT_OTH);
	}

	public static class PepperOptions {
		public static final MacAlgorithm CMAC_ALG = MacAlgorithm.AesCmac256;
		public static final MacAlgorithm HMAC_ALG = MacAlgorithm.HmacSHA256;
		public static final DigestAlgorithm DER_ALG = DigestAlgorithm.SHA256;
		public static final Base64Util.EncoderDecoder ENC_DEC = Base64Util.STD;
	}

	public static class PreSalt {
		public static final SecretKey CKEY = new SecretKeySpec(new byte[32], PepperOptions.CMAC_ALG.algorithm());
		public static final SecretKey HKEY = new SecretKeySpec("pre-salt-key".getBytes(StandardCharsets.UTF_8), PepperOptions.HMAC_ALG.algorithm());

		public static final HashPepperInputVariables NULL   = null;
		public static final HashPepperInputVariables NONE   = new HashPepperInputVariables(new Pepper(null, null,                  new byte[0], new byte[0], PepperOptions.HMAC_ALG, PepperOptions.ENC_DEC));
		public static final HashPepperInputVariables CTX    = new HashPepperInputVariables(new Pepper(null, null,                  new byte[7], new byte[3], PepperOptions.HMAC_ALG, PepperOptions.ENC_DEC));
		public static final HashPepperInputVariables HSK    = new HashPepperInputVariables(new Pepper(HKEY, null,                  new byte[0], new byte[0], PepperOptions.HMAC_ALG, PepperOptions.ENC_DEC));
		public static final HashPepperInputVariables HSKCTX = new HashPepperInputVariables(new Pepper(HKEY, null,                  new byte[3], new byte[2], PepperOptions.HMAC_ALG, PepperOptions.ENC_DEC));
		public static final HashPepperInputVariables CSK    = new HashPepperInputVariables(new Pepper(CKEY, PepperOptions.DER_ALG, new byte[0], new byte[0], PepperOptions.CMAC_ALG, PepperOptions.ENC_DEC));
		public static final HashPepperInputVariables CSKCTX = new HashPepperInputVariables(new Pepper(CKEY, PepperOptions.DER_ALG, new byte[3], new byte[2], PepperOptions.CMAC_ALG, PepperOptions.ENC_DEC));
	}

	public static class PreHash {
		public static final SecretKey CKEY = new SecretKeySpec(new byte[32], PepperOptions.CMAC_ALG.algorithm());
		public static final SecretKey HKEY = new SecretKeySpec("pre-hash-key".getBytes(StandardCharsets.UTF_8), PepperOptions.HMAC_ALG.algorithm());

		public static final HashPepperPreHash NULL   = null;
		public static final HashPepperPreHash NONE   = new HashPepperPreHash(new Pepper(null,  null,                  new byte[0], new byte[0], PepperOptions.HMAC_ALG, PepperOptions.ENC_DEC));
		public static final HashPepperPreHash CTX    = new HashPepperPreHash(new Pepper(null,  null,                  new byte[7], new byte[3], PepperOptions.HMAC_ALG, PepperOptions.ENC_DEC));
		public static final HashPepperPreHash HSK    = new HashPepperPreHash(new Pepper(HKEY,  null,                  new byte[0], new byte[0], PepperOptions.HMAC_ALG, PepperOptions.ENC_DEC));
		public static final HashPepperPreHash HSKCTX = new HashPepperPreHash(new Pepper(HKEY,  null,                  new byte[3], new byte[2], PepperOptions.HMAC_ALG, PepperOptions.ENC_DEC));
		public static final HashPepperPreHash CSK    = new HashPepperPreHash(new Pepper(CKEY,  PepperOptions.DER_ALG, new byte[0], new byte[0], PepperOptions.CMAC_ALG, PepperOptions.ENC_DEC));
		public static final HashPepperPreHash CSKCTX = new HashPepperPreHash(new Pepper(CKEY,  PepperOptions.DER_ALG, new byte[3], new byte[2], PepperOptions.CMAC_ALG, PepperOptions.ENC_DEC));
	}

	public static class PostHash {
		public static final SecretKey CKEY = new SecretKeySpec(new byte[32], PepperOptions.CMAC_ALG.algorithm());
		public static final SecretKey HKEY = new SecretKeySpec("post-hash-key".getBytes(StandardCharsets.UTF_8), PepperOptions.HMAC_ALG.algorithm());

		public static final HashPepperPostHash NULL   = null;
		public static final HashPepperPostHash NONE   = new HashPepperPostHash(new Pepper(null,  null,                  new byte[0], new byte[0], PepperOptions.HMAC_ALG, PepperOptions.ENC_DEC));
		public static final HashPepperPostHash CTX    = new HashPepperPostHash(new Pepper(null,  null,                  new byte[7], new byte[3], PepperOptions.HMAC_ALG, PepperOptions.ENC_DEC));
		public static final HashPepperPostHash HSK    = new HashPepperPostHash(new Pepper(HKEY,  null,                  new byte[0], new byte[0], PepperOptions.HMAC_ALG, PepperOptions.ENC_DEC));
		public static final HashPepperPostHash HSKCTX = new HashPepperPostHash(new Pepper(HKEY,  null,                  new byte[3], new byte[2], PepperOptions.HMAC_ALG, PepperOptions.ENC_DEC));
		public static final HashPepperPostHash CSK    = new HashPepperPostHash(new Pepper(CKEY,  PepperOptions.DER_ALG, new byte[0], new byte[0], PepperOptions.CMAC_ALG, PepperOptions.ENC_DEC));
		public static final HashPepperPostHash CSKCTX = new HashPepperPostHash(new Pepper(CKEY,  PepperOptions.DER_ALG, new byte[3], new byte[2], PepperOptions.CMAC_ALG, PepperOptions.ENC_DEC));
	}

	// 125 Tuples of Peppers => PeppperPreSalt{NULL,NONE,CTX,SK,SKCTX} x PeppperPreHash{NULL,NONE,CTX,SK,SKCTX} x PeppperPostHash{NULL,NONE,CTX,SK,SKCTX})
	public static class Peppers {
		public static final HashPeppers NULL_NULL_NULL       = new HashPeppers(PreSalt.NULL,   PreHash.NULL,   PostHash.NULL);
		public static final HashPeppers NONE_NONE_NONE       = new HashPeppers(PreSalt.NONE,   PreHash.NONE,   PostHash.NONE);
		public static final HashPeppers CTX_CTX_CTX          = new HashPeppers(PreSalt.CTX,    PreHash.CTX,    PostHash.CTX);
		public static final HashPeppers HSK_HSK_HSK          = new HashPeppers(PreSalt.HSK,    PreHash.HSK,    PostHash.HSK);
		public static final HashPeppers HSKCTX_HSKCTX_HSKCTX = new HashPeppers(PreSalt.HSKCTX, PreHash.HSKCTX, PostHash.HSKCTX);
		public static final HashPeppers CSK_CSK_CSK          = new HashPeppers(PreSalt.CSK,    PreHash.CSK,    PostHash.CSK);
		public static final HashPeppers CSKCTX_CSKCTX_CSKCTX = new HashPeppers(PreSalt.CSKCTX, PreHash.CSKCTX, PostHash.CSKCTX);
	}

	// Key+Context pairs for Macs
	public static class ParametersAndPeppers {
		public static final HashInputConstantsAndHashPeppers NONE_NULL_NULL_NULL       = new HashInputConstantsAndHashPeppers(Parameters.STD_CB_NONE, Peppers.NULL_NULL_NULL);
		public static final HashInputConstantsAndHashPeppers NONE_NONE_NONE_NONE       = new HashInputConstantsAndHashPeppers(Parameters.STD_CB_NONE, Peppers.NONE_NONE_NONE);
		public static final HashInputConstantsAndHashPeppers NONE_CTX_CTX_CTX          = new HashInputConstantsAndHashPeppers(Parameters.STD_CB_NONE, Peppers.CTX_CTX_CTX);
		public static final HashInputConstantsAndHashPeppers NONE_HSK_HSK_HSK          = new HashInputConstantsAndHashPeppers(Parameters.STD_CB_NONE, Peppers.HSK_HSK_HSK);
		public static final HashInputConstantsAndHashPeppers NONE_HSKCTX_HSKCTX_HSKCTX = new HashInputConstantsAndHashPeppers(Parameters.STD_CB_NONE, Peppers.HSKCTX_HSKCTX_HSKCTX);
		public static final HashInputConstantsAndHashPeppers NONE_CSK_CSK_CSK          = new HashInputConstantsAndHashPeppers(Parameters.STD_CB_NONE, Peppers.CSK_CSK_CSK);
		public static final HashInputConstantsAndHashPeppers NONE_CSKCTX_CSKCTX_CSKCTX = new HashInputConstantsAndHashPeppers(Parameters.STD_CB_NONE, Peppers.CSKCTX_CSKCTX_CSKCTX);

		public static final HashInputConstantsAndHashPeppers SALT_NULL_NULL_NULL       = new HashInputConstantsAndHashPeppers(Parameters.STD_CB_SALT, Peppers.NULL_NULL_NULL);
		public static final HashInputConstantsAndHashPeppers SALT_NONE_NONE_NONE       = new HashInputConstantsAndHashPeppers(Parameters.STD_CB_SALT, Peppers.NONE_NONE_NONE);
		public static final HashInputConstantsAndHashPeppers SALT_CTX_CTX_CTX          = new HashInputConstantsAndHashPeppers(Parameters.STD_CB_SALT, Peppers.CTX_CTX_CTX);
		public static final HashInputConstantsAndHashPeppers SALT_HSK_HSK_HSK          = new HashInputConstantsAndHashPeppers(Parameters.STD_CB_SALT, Peppers.HSK_HSK_HSK);
		public static final HashInputConstantsAndHashPeppers SALT_HSKCTX_HSKCTX_HSKCTX = new HashInputConstantsAndHashPeppers(Parameters.STD_CB_SALT, Peppers.HSKCTX_HSKCTX_HSKCTX);
		public static final HashInputConstantsAndHashPeppers SALT_CSK_CSK_CSK          = new HashInputConstantsAndHashPeppers(Parameters.STD_CB_SALT, Peppers.CSK_CSK_CSK);
		public static final HashInputConstantsAndHashPeppers SALT_CSKCTX_CSKCTX_CSKCTX = new HashInputConstantsAndHashPeppers(Parameters.STD_CB_SALT, Peppers.CSKCTX_CSKCTX_CSKCTX);

		public static final HashInputConstantsAndHashPeppers OTH_NULL_NULL_NULL       = new HashInputConstantsAndHashPeppers(Parameters.STD_CB_OTH, Peppers.NULL_NULL_NULL);
		public static final HashInputConstantsAndHashPeppers OTH_NONE_NONE_NONE       = new HashInputConstantsAndHashPeppers(Parameters.STD_CB_OTH, Peppers.NONE_NONE_NONE);
		public static final HashInputConstantsAndHashPeppers OTH_CTX_CTX_CTX          = new HashInputConstantsAndHashPeppers(Parameters.STD_CB_OTH, Peppers.CTX_CTX_CTX);
		public static final HashInputConstantsAndHashPeppers OTH_HSK_HSK_HSK          = new HashInputConstantsAndHashPeppers(Parameters.STD_CB_OTH, Peppers.HSK_HSK_HSK);
		public static final HashInputConstantsAndHashPeppers OTH_HSKCTX_HSKCTX_HSKCTX = new HashInputConstantsAndHashPeppers(Parameters.STD_CB_OTH, Peppers.HSKCTX_HSKCTX_HSKCTX);
		public static final HashInputConstantsAndHashPeppers OTH_CSK_CSK_CSK          = new HashInputConstantsAndHashPeppers(Parameters.STD_CB_OTH, Peppers.CSK_CSK_CSK);
		public static final HashInputConstantsAndHashPeppers OTH_CSKCTX_CSKCTX_CSKCTX = new HashInputConstantsAndHashPeppers(Parameters.STD_CB_OTH, Peppers.CSKCTX_CSKCTX_CSKCTX);

		public static final HashInputConstantsAndHashPeppers SALTOTH_NULL_NULL_NULL       = new HashInputConstantsAndHashPeppers(Parameters.STD_CB_SALT_OTH, Peppers.NULL_NULL_NULL);
		public static final HashInputConstantsAndHashPeppers SALTOTH_NONE_NONE_NONE       = new HashInputConstantsAndHashPeppers(Parameters.STD_CB_SALT_OTH, Peppers.NONE_NONE_NONE);
		public static final HashInputConstantsAndHashPeppers SALTOTH_CTX_CTX_CTX          = new HashInputConstantsAndHashPeppers(Parameters.STD_CB_SALT_OTH, Peppers.CTX_CTX_CTX);
		public static final HashInputConstantsAndHashPeppers SALTOTH_HSK_HSK_HSK          = new HashInputConstantsAndHashPeppers(Parameters.STD_CB_SALT_OTH, Peppers.HSK_HSK_HSK);
		public static final HashInputConstantsAndHashPeppers SALTOTH_HSKCTX_HSKCTX_HSKCTX = new HashInputConstantsAndHashPeppers(Parameters.STD_CB_SALT_OTH, Peppers.HSKCTX_HSKCTX_HSKCTX);
		public static final HashInputConstantsAndHashPeppers SALTOTH_CSK_CSK_CSK          = new HashInputConstantsAndHashPeppers(Parameters.STD_CB_SALT_OTH, Peppers.CSK_CSK_CSK);
		public static final HashInputConstantsAndHashPeppers SALTOTH_CSKCTX_CSKCTX_CSKCTX = new HashInputConstantsAndHashPeppers(Parameters.STD_CB_SALT_OTH, Peppers.CSKCTX_CSKCTX_CSKCTX);
	}
}
