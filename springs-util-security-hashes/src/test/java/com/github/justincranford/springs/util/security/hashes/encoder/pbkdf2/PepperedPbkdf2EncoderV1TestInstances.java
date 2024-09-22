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
import com.github.justincranford.springs.util.security.hashes.mac.CmacAlgorithm;
import com.github.justincranford.springs.util.security.hashes.mac.HmacAlgorithm;

import lombok.AccessLevel;
import lombok.NoArgsConstructor;

@SuppressWarnings({"nls"})
@NoArgsConstructor(access=AccessLevel.PRIVATE)
public final class PepperedPbkdf2EncoderV1TestInstances {
	public static final class Random {
		public static final RandomSalt VARS_CONS_NULL_NULL_NULL       = new RandomSalt(ParametersAndPeppers.VARS_CONS_NULL_NULL_NULL,       Defaults.RAND_LEN_BYTES);
		public static final RandomSalt VARS_CONS_NONE_NONE_NONE       = new RandomSalt(ParametersAndPeppers.VARS_CONS_NONE_NONE_NONE,       Defaults.RAND_LEN_BYTES);
		public static final RandomSalt VARS_CONS_CTX_CTX_CTX          = new RandomSalt(ParametersAndPeppers.VARS_CONS_CTX_CTX_CTX,          Defaults.RAND_LEN_BYTES);
		public static final RandomSalt VARS_CONS_HSK_HSK_HSK          = new RandomSalt(ParametersAndPeppers.VARS_CONS_HSK_HSK_HSK,          Defaults.RAND_LEN_BYTES);
		public static final RandomSalt VARS_CONS_HSKCTX_HSKCTX_HSKCTX = new RandomSalt(ParametersAndPeppers.VARS_CONS_HSKCTX_HSKCTX_HSKCTX, Defaults.RAND_LEN_BYTES);
		public static final RandomSalt VARS_CONS_CSK_CSK_CSK          = new RandomSalt(ParametersAndPeppers.VARS_CONS_CSK_CSK_CSK,          Defaults.RAND_LEN_BYTES);
		public static final RandomSalt VARS_CONS_CSKCTX_CSKCTX_CSKCTX = new RandomSalt(ParametersAndPeppers.VARS_CONS_CSKCTX_CSKCTX_CSKCTX, Defaults.RAND_LEN_BYTES);

		public static final RandomSalt VARS_NULL_NULL_NULL          = new RandomSalt(ParametersAndPeppers.VARS_NULL_NULL_NULL,          Defaults.RAND_LEN_BYTES);
		public static final RandomSalt VARS_NONE_NONE_NONE          = new RandomSalt(ParametersAndPeppers.VARS_NONE_NONE_NONE,          Defaults.RAND_LEN_BYTES);
		public static final RandomSalt VARS_CTX_CTX_CTX             = new RandomSalt(ParametersAndPeppers.VARS_CTX_CTX_CTX,             Defaults.RAND_LEN_BYTES);
		public static final RandomSalt VARS_HSK_HSK_HSK             = new RandomSalt(ParametersAndPeppers.VARS_HSK_HSK_HSK,             Defaults.RAND_LEN_BYTES);
		public static final RandomSalt VARS_HSKCTX_HSKCTX_HSKCTX    = new RandomSalt(ParametersAndPeppers.VARS_HSKCTX_HSKCTX_HSKCTX,    Defaults.RAND_LEN_BYTES);
		public static final RandomSalt VARS_CSK_CSK_CSK             = new RandomSalt(ParametersAndPeppers.VARS_CSK_CSK_CSK,             Defaults.RAND_LEN_BYTES);
		public static final RandomSalt VARS_CSKCTX_CSKCTX_CSKCTX    = new RandomSalt(ParametersAndPeppers.VARS_CSKCTX_CSKCTX_CSKCTX,    Defaults.RAND_LEN_BYTES);
	}

	public static final class Derived {
//		public static final DerivedSalt VARS_CONS_NULL_NULL_NULL       = new DerivedSalt(ParametersAndPeppers.VARS_CONS_NULL_NULL_NULL, Defaults.DER_LEN_BYTES);
		public static final DerivedSalt VARS_CONS_NONE_NONE_NONE       = new DerivedSalt(ParametersAndPeppers.VARS_CONS_NONE_NONE_NONE, Defaults.DER_LEN_BYTES);
		public static final DerivedSalt VARS_CONS_CTX_CTX_CTX          = new DerivedSalt(ParametersAndPeppers.VARS_CONS_CTX_CTX_CTX, Defaults.DER_LEN_BYTES);
		public static final DerivedSalt VARS_CONS_HSK_HSK_HSK          = new DerivedSalt(ParametersAndPeppers.VARS_CONS_HSK_HSK_HSK, Defaults.DER_LEN_BYTES);
		public static final DerivedSalt VARS_CONS_HSKCTX_HSKCTX_HSKCTX = new DerivedSalt(ParametersAndPeppers.VARS_CONS_HSKCTX_HSKCTX_HSKCTX, Defaults.DER_LEN_BYTES);
		public static final DerivedSalt VARS_CONS_CSK_CSK_CSK          = new DerivedSalt(ParametersAndPeppers.VARS_CONS_CSK_CSK_CSK, Defaults.DER_LEN_BYTES);
		public static final DerivedSalt VARS_CONS_CSKCTX_CSKCTX_CSKCTX = new DerivedSalt(ParametersAndPeppers.VARS_CONS_CSKCTX_CSKCTX_CSKCTX, Defaults.DER_LEN_BYTES);

//		public static final DerivedSalt VARS_NULL_NULL_NULL       = new DerivedSalt(ParametersAndPeppers.VARS_NULL_NULL_NULL, Defaults.DER_LEN_BYTES);
		public static final DerivedSalt VARS_NONE_NONE_NONE       = new DerivedSalt(ParametersAndPeppers.VARS_NONE_NONE_NONE, Defaults.DER_LEN_BYTES);
		public static final DerivedSalt VARS_CTX_CTX_CTX          = new DerivedSalt(ParametersAndPeppers.VARS_CTX_CTX_CTX, Defaults.DER_LEN_BYTES);
		public static final DerivedSalt VARS_HSK_HSK_HSK          = new DerivedSalt(ParametersAndPeppers.VARS_HSK_HSK_HSK, Defaults.DER_LEN_BYTES);
		public static final DerivedSalt VARS_HSKCTX_HSKCTX_HSKCTX = new DerivedSalt(ParametersAndPeppers.VARS_HSKCTX_HSKCTX_HSKCTX, Defaults.DER_LEN_BYTES);
		public static final DerivedSalt VARS_CSK_CSK_CSK          = new DerivedSalt(ParametersAndPeppers.VARS_CSK_CSK_CSK, Defaults.DER_LEN_BYTES);
		public static final DerivedSalt VARS_CSKCTX_CSKCTX_CSKCTX = new DerivedSalt(ParametersAndPeppers.VARS_CSKCTX_CSKCTX_CSKCTX, Defaults.DER_LEN_BYTES);

//		public static final DerivedSalt CONS_NULL_NULL_NULL       = new DerivedSalt(ParametersAndPeppers.CONS_NULL_NULL_NULL, Defaults.DER_LEN_BYTES);
		public static final DerivedSalt CONS_NONE_NONE_NONE       = new DerivedSalt(ParametersAndPeppers.CONS_NONE_NONE_NONE, Defaults.DER_LEN_BYTES);
		public static final DerivedSalt CONS_CTX_CTX_CTX          = new DerivedSalt(ParametersAndPeppers.CONS_CTX_CTX_CTX, Defaults.DER_LEN_BYTES);
		public static final DerivedSalt CONS_HSK_HSK_HSK          = new DerivedSalt(ParametersAndPeppers.CONS_HSK_HSK_HSK, Defaults.DER_LEN_BYTES);
		public static final DerivedSalt CONS_HSKCTX_HSKCTX_HSKCTX = new DerivedSalt(ParametersAndPeppers.CONS_HSKCTX_HSKCTX_HSKCTX, Defaults.DER_LEN_BYTES);
		public static final DerivedSalt CONS_CSK_CSK_CSK          = new DerivedSalt(ParametersAndPeppers.CONS_CSK_CSK_CSK, Defaults.DER_LEN_BYTES);
		public static final DerivedSalt CONS_CSKCTX_CSKCTX_CSKCTX = new DerivedSalt(ParametersAndPeppers.CONS_CSKCTX_CSKCTX_CSKCTX, Defaults.DER_LEN_BYTES);

//		public static final DerivedSalt NONE_NULL_NULL_NULL       = new DerivedSalt(ParametersAndPeppers.NONE_NULL_NULL_NULL, Defaults.DER_LEN_BYTES);
		public static final DerivedSalt NONE_NONE_NONE_NONE       = new DerivedSalt(ParametersAndPeppers.NONE_NONE_NONE_NONE, Defaults.DER_LEN_BYTES);
		public static final DerivedSalt NONE_CTX_CTX_CTX          = new DerivedSalt(ParametersAndPeppers.NONE_CTX_CTX_CTX, Defaults.DER_LEN_BYTES);
		public static final DerivedSalt NONE_HSK_HSK_HSK          = new DerivedSalt(ParametersAndPeppers.NONE_HSK_HSK_HSK, Defaults.DER_LEN_BYTES);
		public static final DerivedSalt NONE_HSKCTX_HSKCTX_HSKCTX = new DerivedSalt(ParametersAndPeppers.NONE_HSKCTX_HSKCTX_HSKCTX, Defaults.DER_LEN_BYTES);
		public static final DerivedSalt NONE_CSK_CSK_CSK          = new DerivedSalt(ParametersAndPeppers.NONE_CSK_CSK_CSK, Defaults.DER_LEN_BYTES);
		public static final DerivedSalt NONE_CSKCTX_CSKCTX_CSKCTX = new DerivedSalt(ParametersAndPeppers.NONE_CSKCTX_CSKCTX_CSKCTX, Defaults.DER_LEN_BYTES);
	}

	public static final class Constant {
		public static final ConstantSalt VARS_CONS_NULL_NULL_NULL       = new ConstantSalt(ParametersAndPeppers.VARS_CONS_NULL_NULL_NULL, Defaults.CONST_BYTES);
		public static final ConstantSalt VARS_CONS_NONE_NONE_NONE       = new ConstantSalt(ParametersAndPeppers.VARS_CONS_NONE_NONE_NONE, Defaults.CONST_BYTES);
		public static final ConstantSalt VARS_CONS_CTX_CTX_CTX          = new ConstantSalt(ParametersAndPeppers.VARS_CONS_CTX_CTX_CTX, Defaults.CONST_BYTES);
		public static final ConstantSalt VARS_CONS_HSK_HSK_HSK          = new ConstantSalt(ParametersAndPeppers.VARS_CONS_HSK_HSK_HSK, Defaults.CONST_BYTES);
		public static final ConstantSalt VARS_CONS_HSKCTX_HSKCTX_HSKCTX = new ConstantSalt(ParametersAndPeppers.VARS_CONS_HSKCTX_HSKCTX_HSKCTX, Defaults.CONST_BYTES);
		public static final ConstantSalt VARS_CONS_CSK_CSK_CSK          = new ConstantSalt(ParametersAndPeppers.VARS_CONS_CSK_CSK_CSK, Defaults.CONST_BYTES);
		public static final ConstantSalt VARS_CONS_CSKCTX_CSKCTX_CSKCTX = new ConstantSalt(ParametersAndPeppers.VARS_CONS_CSKCTX_CSKCTX_CSKCTX, Defaults.CONST_BYTES);

		public static final ConstantSalt VARS_NULL_NULL_NULL       = new ConstantSalt(ParametersAndPeppers.VARS_NULL_NULL_NULL, Defaults.CONST_BYTES);
		public static final ConstantSalt VARS_NONE_NONE_NONE       = new ConstantSalt(ParametersAndPeppers.VARS_NONE_NONE_NONE, Defaults.CONST_BYTES);
		public static final ConstantSalt VARS_CTX_CTX_CTX          = new ConstantSalt(ParametersAndPeppers.VARS_CTX_CTX_CTX, Defaults.CONST_BYTES);
		public static final ConstantSalt VARS_HSK_HSK_HSK          = new ConstantSalt(ParametersAndPeppers.VARS_HSK_HSK_HSK, Defaults.CONST_BYTES);
		public static final ConstantSalt VARS_HSKCTX_HSKCTX_HSKCTX = new ConstantSalt(ParametersAndPeppers.VARS_HSKCTX_HSKCTX_HSKCTX, Defaults.CONST_BYTES);
		public static final ConstantSalt VARS_CSK_CSK_CSK          = new ConstantSalt(ParametersAndPeppers.VARS_CSK_CSK_CSK, Defaults.CONST_BYTES);
		public static final ConstantSalt VARS_CSKCTX_CSKCTX_CSKCTX = new ConstantSalt(ParametersAndPeppers.VARS_CSKCTX_CSKCTX_CSKCTX, Defaults.CONST_BYTES);

		public static final ConstantSalt CONS_NULL_NULL_NULL       = new ConstantSalt(ParametersAndPeppers.CONS_NULL_NULL_NULL, Defaults.CONST_BYTES);
		public static final ConstantSalt CONS_NONE_NONE_NONE       = new ConstantSalt(ParametersAndPeppers.CONS_NONE_NONE_NONE, Defaults.CONST_BYTES);
		public static final ConstantSalt CONS_CTX_CTX_CTX          = new ConstantSalt(ParametersAndPeppers.CONS_CTX_CTX_CTX, Defaults.CONST_BYTES);
		public static final ConstantSalt CONS_HSK_HSK_HSK          = new ConstantSalt(ParametersAndPeppers.CONS_HSK_HSK_HSK, Defaults.CONST_BYTES);
		public static final ConstantSalt CONS_HSKCTX_HSKCTX_HSKCTX = new ConstantSalt(ParametersAndPeppers.CONS_HSKCTX_HSKCTX_HSKCTX, Defaults.CONST_BYTES);
		public static final ConstantSalt CONS_CSK_CSK_CSK          = new ConstantSalt(ParametersAndPeppers.CONS_CSK_CSK_CSK, Defaults.CONST_BYTES);
		public static final ConstantSalt CONS_CSKCTX_CSKCTX_CSKCTX = new ConstantSalt(ParametersAndPeppers.CONS_CSKCTX_CSKCTX_CSKCTX, Defaults.CONST_BYTES);

		public static final ConstantSalt NONE_NULL_NULL_NULL       = new ConstantSalt(ParametersAndPeppers.NONE_NULL_NULL_NULL, Defaults.CONST_BYTES);
		public static final ConstantSalt NONE_NONE_NONE_NONE       = new ConstantSalt(ParametersAndPeppers.NONE_NONE_NONE_NONE, Defaults.CONST_BYTES);
		public static final ConstantSalt NONE_CTX_CTX_CTX          = new ConstantSalt(ParametersAndPeppers.NONE_CTX_CTX_CTX, Defaults.CONST_BYTES);
		public static final ConstantSalt NONE_HSK_HSK_HSK          = new ConstantSalt(ParametersAndPeppers.NONE_HSK_HSK_HSK, Defaults.CONST_BYTES);
		public static final ConstantSalt NONE_HSKCTX_HSKCTX_HSKCTX = new ConstantSalt(ParametersAndPeppers.NONE_HSKCTX_HSKCTX_HSKCTX, Defaults.CONST_BYTES);
		public static final ConstantSalt NONE_CSK_CSK_CSK          = new ConstantSalt(ParametersAndPeppers.NONE_CSK_CSK_CSK, Defaults.CONST_BYTES);
		public static final ConstantSalt NONE_CSKCTX_CSKCTX_CSKCTX = new ConstantSalt(ParametersAndPeppers.NONE_CSKCTX_CSKCTX_CSKCTX, Defaults.CONST_BYTES);
	}

	public static class Defaults {
		public static final int ITER = 600_000;
		public static final int DK_BYTES_LEN = 32;
		public static final Pbkdf2AlgorithmV1 PRF_ALG = Pbkdf2AlgorithmV1.PBKDF2WithHmacSHA256;

		public static final int RAND_LEN_BYTES = 32;
		public static final int DER_LEN_BYTES = 32;
		public static final byte[] CONST_BYTES = "constant-salt-bytes".getBytes(StandardCharsets.UTF_8);

		public static final HashCodec B64_STD_CB_NONE     = new HashCodec(TextCodec.B64_STD, "|", ":", Flags.NONE);
		public static final HashCodec B64_STD_CB_VARS     = new HashCodec(TextCodec.B64_STD, "|", ":", Flags.VARS);
		public static final HashCodec B64_STD_CB_CONS      = new HashCodec(TextCodec.B64_STD, "|", ":", Flags.CONS);
		public static final HashCodec B64_STD_CB_VARS_CONS = new HashCodec(TextCodec.B64_STD, "|", ":", Flags.BOTH);
	}

	public static class Parameters {
		public static final Pbkdf2InputConstantsV1 B64_STD_CB_VARS_CONS = new Pbkdf2InputConstantsV1(Defaults.PRF_ALG, Defaults.B64_STD_CB_VARS_CONS, Defaults.DK_BYTES_LEN, Defaults.ITER);
		public static final Pbkdf2InputConstantsV1 B64_STD_CB_VARS      = new Pbkdf2InputConstantsV1(Defaults.PRF_ALG, Defaults.B64_STD_CB_VARS, Defaults.DK_BYTES_LEN, Defaults.ITER);
		public static final Pbkdf2InputConstantsV1 B64_STD_CB_CONS      = new Pbkdf2InputConstantsV1(Defaults.PRF_ALG, Defaults.B64_STD_CB_CONS, Defaults.DK_BYTES_LEN, Defaults.ITER);
		public static final Pbkdf2InputConstantsV1 B64_STD_CB_NONE      = new Pbkdf2InputConstantsV1(Defaults.PRF_ALG, Defaults.B64_STD_CB_NONE, Defaults.DK_BYTES_LEN, Defaults.ITER);
	}

	public static class PepperOptions {
		public static final CmacAlgorithm CMAC_ALG = CmacAlgorithm.AesCmac256;
		public static final HmacAlgorithm HMAC_ALG = HmacAlgorithm.HmacSHA256;
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
		public static final HashInputConstantsAndHashPeppers NONE_NULL_NULL_NULL       = new HashInputConstantsAndHashPeppers(Parameters.B64_STD_CB_NONE, Peppers.NULL_NULL_NULL);
		public static final HashInputConstantsAndHashPeppers NONE_NONE_NONE_NONE       = new HashInputConstantsAndHashPeppers(Parameters.B64_STD_CB_NONE, Peppers.NONE_NONE_NONE);
		public static final HashInputConstantsAndHashPeppers NONE_CTX_CTX_CTX          = new HashInputConstantsAndHashPeppers(Parameters.B64_STD_CB_NONE, Peppers.CTX_CTX_CTX);
		public static final HashInputConstantsAndHashPeppers NONE_HSK_HSK_HSK          = new HashInputConstantsAndHashPeppers(Parameters.B64_STD_CB_NONE, Peppers.HSK_HSK_HSK);
		public static final HashInputConstantsAndHashPeppers NONE_HSKCTX_HSKCTX_HSKCTX = new HashInputConstantsAndHashPeppers(Parameters.B64_STD_CB_NONE, Peppers.HSKCTX_HSKCTX_HSKCTX);
		public static final HashInputConstantsAndHashPeppers NONE_CSK_CSK_CSK          = new HashInputConstantsAndHashPeppers(Parameters.B64_STD_CB_NONE, Peppers.CSK_CSK_CSK);
		public static final HashInputConstantsAndHashPeppers NONE_CSKCTX_CSKCTX_CSKCTX = new HashInputConstantsAndHashPeppers(Parameters.B64_STD_CB_NONE, Peppers.CSKCTX_CSKCTX_CSKCTX);

		public static final HashInputConstantsAndHashPeppers VARS_NULL_NULL_NULL       = new HashInputConstantsAndHashPeppers(Parameters.B64_STD_CB_VARS, Peppers.NULL_NULL_NULL);
		public static final HashInputConstantsAndHashPeppers VARS_NONE_NONE_NONE       = new HashInputConstantsAndHashPeppers(Parameters.B64_STD_CB_VARS, Peppers.NONE_NONE_NONE);
		public static final HashInputConstantsAndHashPeppers VARS_CTX_CTX_CTX          = new HashInputConstantsAndHashPeppers(Parameters.B64_STD_CB_VARS, Peppers.CTX_CTX_CTX);
		public static final HashInputConstantsAndHashPeppers VARS_HSK_HSK_HSK          = new HashInputConstantsAndHashPeppers(Parameters.B64_STD_CB_VARS, Peppers.HSK_HSK_HSK);
		public static final HashInputConstantsAndHashPeppers VARS_HSKCTX_HSKCTX_HSKCTX = new HashInputConstantsAndHashPeppers(Parameters.B64_STD_CB_VARS, Peppers.HSKCTX_HSKCTX_HSKCTX);
		public static final HashInputConstantsAndHashPeppers VARS_CSK_CSK_CSK          = new HashInputConstantsAndHashPeppers(Parameters.B64_STD_CB_VARS, Peppers.CSK_CSK_CSK);
		public static final HashInputConstantsAndHashPeppers VARS_CSKCTX_CSKCTX_CSKCTX = new HashInputConstantsAndHashPeppers(Parameters.B64_STD_CB_VARS, Peppers.CSKCTX_CSKCTX_CSKCTX);

		public static final HashInputConstantsAndHashPeppers CONS_NULL_NULL_NULL       = new HashInputConstantsAndHashPeppers(Parameters.B64_STD_CB_CONS, Peppers.NULL_NULL_NULL);
		public static final HashInputConstantsAndHashPeppers CONS_NONE_NONE_NONE       = new HashInputConstantsAndHashPeppers(Parameters.B64_STD_CB_CONS, Peppers.NONE_NONE_NONE);
		public static final HashInputConstantsAndHashPeppers CONS_CTX_CTX_CTX          = new HashInputConstantsAndHashPeppers(Parameters.B64_STD_CB_CONS, Peppers.CTX_CTX_CTX);
		public static final HashInputConstantsAndHashPeppers CONS_HSK_HSK_HSK          = new HashInputConstantsAndHashPeppers(Parameters.B64_STD_CB_CONS, Peppers.HSK_HSK_HSK);
		public static final HashInputConstantsAndHashPeppers CONS_HSKCTX_HSKCTX_HSKCTX = new HashInputConstantsAndHashPeppers(Parameters.B64_STD_CB_CONS, Peppers.HSKCTX_HSKCTX_HSKCTX);
		public static final HashInputConstantsAndHashPeppers CONS_CSK_CSK_CSK          = new HashInputConstantsAndHashPeppers(Parameters.B64_STD_CB_CONS, Peppers.CSK_CSK_CSK);
		public static final HashInputConstantsAndHashPeppers CONS_CSKCTX_CSKCTX_CSKCTX = new HashInputConstantsAndHashPeppers(Parameters.B64_STD_CB_CONS, Peppers.CSKCTX_CSKCTX_CSKCTX);

		public static final HashInputConstantsAndHashPeppers VARS_CONS_NULL_NULL_NULL       = new HashInputConstantsAndHashPeppers(Parameters.B64_STD_CB_VARS_CONS, Peppers.NULL_NULL_NULL);
		public static final HashInputConstantsAndHashPeppers VARS_CONS_NONE_NONE_NONE       = new HashInputConstantsAndHashPeppers(Parameters.B64_STD_CB_VARS_CONS, Peppers.NONE_NONE_NONE);
		public static final HashInputConstantsAndHashPeppers VARS_CONS_CTX_CTX_CTX          = new HashInputConstantsAndHashPeppers(Parameters.B64_STD_CB_VARS_CONS, Peppers.CTX_CTX_CTX);
		public static final HashInputConstantsAndHashPeppers VARS_CONS_HSK_HSK_HSK          = new HashInputConstantsAndHashPeppers(Parameters.B64_STD_CB_VARS_CONS, Peppers.HSK_HSK_HSK);
		public static final HashInputConstantsAndHashPeppers VARS_CONS_HSKCTX_HSKCTX_HSKCTX = new HashInputConstantsAndHashPeppers(Parameters.B64_STD_CB_VARS_CONS, Peppers.HSKCTX_HSKCTX_HSKCTX);
		public static final HashInputConstantsAndHashPeppers VARS_CONS_CSK_CSK_CSK          = new HashInputConstantsAndHashPeppers(Parameters.B64_STD_CB_VARS_CONS, Peppers.CSK_CSK_CSK);
		public static final HashInputConstantsAndHashPeppers VARS_CONS_CSKCTX_CSKCTX_CSKCTX = new HashInputConstantsAndHashPeppers(Parameters.B64_STD_CB_VARS_CONS, Peppers.CSKCTX_CSKCTX_CSKCTX);
	}
}
