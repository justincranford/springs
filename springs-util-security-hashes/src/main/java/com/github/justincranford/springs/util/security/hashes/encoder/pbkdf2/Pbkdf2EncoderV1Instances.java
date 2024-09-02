package com.github.justincranford.springs.util.security.hashes.encoder.pbkdf2;

import java.nio.charset.StandardCharsets;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import com.github.justincranford.springs.util.basic.Base64Util;
import com.github.justincranford.springs.util.security.hashes.encoder.model.HashEncodeDecode;
import com.github.justincranford.springs.util.security.hashes.encoder.model.Mac;
import com.github.justincranford.springs.util.security.hashes.encoder.model.Macs;
import com.github.justincranford.springs.util.security.hashes.encoder.model.ParametersAndMacs;
import com.github.justincranford.springs.util.security.hashes.encoder.pbkdf2.Pbkdf2EncoderV1.ConstantSalt;
import com.github.justincranford.springs.util.security.hashes.encoder.pbkdf2.Pbkdf2EncoderV1.DerivedSalt;
import com.github.justincranford.springs.util.security.hashes.encoder.pbkdf2.Pbkdf2EncoderV1.RandomSalt;
import com.github.justincranford.springs.util.security.hashes.util.MacAlgorithm;

import lombok.AccessLevel;
import lombok.NoArgsConstructor;

@SuppressWarnings({"nls"})
@NoArgsConstructor(access=AccessLevel.PRIVATE)
public final class Pbkdf2EncoderV1Instances {
	public static final class Random {
		public static final RandomSalt SALTOTH_NULL_NULL_NULL    = new RandomSalt(ParametersAndPeppers.SALTOTH_NULL_NULL_NULL,       Defaults.RAND_LEN_BYTES);
		public static final RandomSalt SALTOTH_NONE_NONE_NONE    = new RandomSalt(ParametersAndPeppers.SALTOTH_NONE_NONE_NONE,       Defaults.RAND_LEN_BYTES);
		public static final RandomSalt SALTOTH_CTX_CTX_CTX       = new RandomSalt(ParametersAndPeppers.SALTOTH_CTX_CTX_CTX,          Defaults.RAND_LEN_BYTES);
		public static final RandomSalt SALTOTH_SK_SK_SK          = new RandomSalt(ParametersAndPeppers.SALTOTH_SK_SK_SK,             Defaults.RAND_LEN_BYTES);
		public static final RandomSalt SALTOTH_SKCTX_SKCTX_SKCTX = new RandomSalt(ParametersAndPeppers.SALTOTH_SKCTX_SKCTX_SKCTX,    Defaults.RAND_LEN_BYTES);
		public static final RandomSalt SALT_NULL_NULL_NULL       = new RandomSalt(ParametersAndPeppers.SALT_NULL_NULL_NULL,          Defaults.RAND_LEN_BYTES);
		public static final RandomSalt SALT_NONE_NONE_NONE       = new RandomSalt(ParametersAndPeppers.SALT_NONE_NONE_NONE,          Defaults.RAND_LEN_BYTES);
		public static final RandomSalt SALT_CTX_CTX_CTX          = new RandomSalt(ParametersAndPeppers.SALT_CTX_CTX_CTX,             Defaults.RAND_LEN_BYTES);
		public static final RandomSalt SALT_SK_SK_SK             = new RandomSalt(ParametersAndPeppers.SALT_SK_SK_SK,                Defaults.RAND_LEN_BYTES);
		public static final RandomSalt SALT_SKCTX_SKCTX_SKCTX    = new RandomSalt(ParametersAndPeppers.SALT_SKCTX_SKCTX_SKCTX,       Defaults.RAND_LEN_BYTES);
	}

	public static final class Derived {
		public static final DerivedSalt NONE_NULL_NULL_NULL    = new DerivedSalt(ParametersAndPeppers.NONE_NULL_NULL_NULL, Defaults.DER_LEN_BYTES);
		public static final DerivedSalt NONE_NONE_NONE_NONE    = new DerivedSalt(ParametersAndPeppers.NONE_NONE_NONE_NONE, Defaults.DER_LEN_BYTES);
		public static final DerivedSalt NONE_CTX_CTX_CTX       = new DerivedSalt(ParametersAndPeppers.NONE_CTX_CTX_CTX, Defaults.DER_LEN_BYTES);
		public static final DerivedSalt NONE_SK_SK_SK          = new DerivedSalt(ParametersAndPeppers.NONE_SK_SK_SK, Defaults.DER_LEN_BYTES);
		public static final DerivedSalt NONE_SKCTX_SKCTX_SKCTX = new DerivedSalt(ParametersAndPeppers.NONE_SKCTX_SKCTX_SKCTX, Defaults.DER_LEN_BYTES);

		public static final DerivedSalt SALT_NULL_NULL_NULL    = new DerivedSalt(ParametersAndPeppers.SALT_NULL_NULL_NULL, Defaults.DER_LEN_BYTES);
		public static final DerivedSalt SALT_NONE_NONE_NONE    = new DerivedSalt(ParametersAndPeppers.SALT_NONE_NONE_NONE, Defaults.DER_LEN_BYTES);
		public static final DerivedSalt SALT_CTX_CTX_CTX       = new DerivedSalt(ParametersAndPeppers.SALT_CTX_CTX_CTX, Defaults.DER_LEN_BYTES);
		public static final DerivedSalt SALT_SK_SK_SK          = new DerivedSalt(ParametersAndPeppers.SALT_SK_SK_SK, Defaults.DER_LEN_BYTES);
		public static final DerivedSalt SALT_SKCTX_SKCTX_SKCTX = new DerivedSalt(ParametersAndPeppers.SALT_SKCTX_SKCTX_SKCTX, Defaults.DER_LEN_BYTES);

		public static final DerivedSalt OTH_NULL_NULL_NULL    = new DerivedSalt(ParametersAndPeppers.OTH_NULL_NULL_NULL, Defaults.DER_LEN_BYTES);
		public static final DerivedSalt OTH_NONE_NONE_NONE    = new DerivedSalt(ParametersAndPeppers.OTH_NONE_NONE_NONE, Defaults.DER_LEN_BYTES);
		public static final DerivedSalt OTH_CTX_CTX_CTX       = new DerivedSalt(ParametersAndPeppers.OTH_CTX_CTX_CTX, Defaults.DER_LEN_BYTES);
		public static final DerivedSalt OTH_SK_SK_SK          = new DerivedSalt(ParametersAndPeppers.OTH_SK_SK_SK, Defaults.DER_LEN_BYTES);
		public static final DerivedSalt OTH_SKCTX_SKCTX_SKCTX = new DerivedSalt(ParametersAndPeppers.OTH_SKCTX_SKCTX_SKCTX, Defaults.DER_LEN_BYTES);

		public static final DerivedSalt SALTOTH_NULL_NULL_NULL    = new DerivedSalt(ParametersAndPeppers.SALTOTH_NULL_NULL_NULL, Defaults.DER_LEN_BYTES);
		public static final DerivedSalt SALTOTH_NONE_NONE_NONE    = new DerivedSalt(ParametersAndPeppers.SALTOTH_NONE_NONE_NONE, Defaults.DER_LEN_BYTES);
		public static final DerivedSalt SALTOTH_CTX_CTX_CTX       = new DerivedSalt(ParametersAndPeppers.SALTOTH_CTX_CTX_CTX, Defaults.DER_LEN_BYTES);
		public static final DerivedSalt SALTOTH_SK_SK_SK          = new DerivedSalt(ParametersAndPeppers.SALTOTH_SK_SK_SK, Defaults.DER_LEN_BYTES);
		public static final DerivedSalt SALTOTH_SKCTX_SKCTX_SKCTX = new DerivedSalt(ParametersAndPeppers.SALTOTH_SKCTX_SKCTX_SKCTX, Defaults.DER_LEN_BYTES);
	}

	public static final class Constant {
		public static final ConstantSalt NONE_NULL_NULL_NULL    = new ConstantSalt(ParametersAndPeppers.NONE_NULL_NULL_NULL, Defaults.CONST_BYTES);
		public static final ConstantSalt NONE_NONE_NONE_NONE    = new ConstantSalt(ParametersAndPeppers.NONE_NONE_NONE_NONE, Defaults.CONST_BYTES);
		public static final ConstantSalt NONE_CTX_CTX_CTX       = new ConstantSalt(ParametersAndPeppers.NONE_CTX_CTX_CTX, Defaults.CONST_BYTES);
		public static final ConstantSalt NONE_SK_SK_SK          = new ConstantSalt(ParametersAndPeppers.NONE_SK_SK_SK, Defaults.CONST_BYTES);
		public static final ConstantSalt NONE_SKCTX_SKCTX_SKCTX = new ConstantSalt(ParametersAndPeppers.NONE_SKCTX_SKCTX_SKCTX, Defaults.CONST_BYTES);

		public static final ConstantSalt SALT_NULL_NULL_NULL    = new ConstantSalt(ParametersAndPeppers.SALT_NULL_NULL_NULL, Defaults.CONST_BYTES);
		public static final ConstantSalt SALT_NONE_NONE_NONE    = new ConstantSalt(ParametersAndPeppers.SALT_NONE_NONE_NONE, Defaults.CONST_BYTES);
		public static final ConstantSalt SALT_CTX_CTX_CTX       = new ConstantSalt(ParametersAndPeppers.SALT_CTX_CTX_CTX, Defaults.CONST_BYTES);
		public static final ConstantSalt SALT_SK_SK_SK          = new ConstantSalt(ParametersAndPeppers.SALT_SK_SK_SK, Defaults.CONST_BYTES);
		public static final ConstantSalt SALT_SKCTX_SKCTX_SKCTX = new ConstantSalt(ParametersAndPeppers.SALT_SKCTX_SKCTX_SKCTX, Defaults.CONST_BYTES);

		public static final ConstantSalt OTH_NULL_NULL_NULL    = new ConstantSalt(ParametersAndPeppers.OTH_NULL_NULL_NULL, Defaults.CONST_BYTES);
		public static final ConstantSalt OTH_NONE_NONE_NONE    = new ConstantSalt(ParametersAndPeppers.OTH_NONE_NONE_NONE, Defaults.CONST_BYTES);
		public static final ConstantSalt OTH_CTX_CTX_CTX       = new ConstantSalt(ParametersAndPeppers.OTH_CTX_CTX_CTX, Defaults.CONST_BYTES);
		public static final ConstantSalt OTH_SK_SK_SK          = new ConstantSalt(ParametersAndPeppers.OTH_SK_SK_SK, Defaults.CONST_BYTES);
		public static final ConstantSalt OTH_SKCTX_SKCTX_SKCTX = new ConstantSalt(ParametersAndPeppers.OTH_SKCTX_SKCTX_SKCTX, Defaults.CONST_BYTES);

		public static final ConstantSalt SALTOTH_NULL_NULL_NULL    = new ConstantSalt(ParametersAndPeppers.SALTOTH_NULL_NULL_NULL, Defaults.CONST_BYTES);
		public static final ConstantSalt SALTOTH_NONE_NONE_NONE    = new ConstantSalt(ParametersAndPeppers.SALTOTH_NONE_NONE_NONE, Defaults.CONST_BYTES);
		public static final ConstantSalt SALTOTH_CTX_CTX_CTX       = new ConstantSalt(ParametersAndPeppers.SALTOTH_CTX_CTX_CTX, Defaults.CONST_BYTES);
		public static final ConstantSalt SALTOTH_SK_SK_SK          = new ConstantSalt(ParametersAndPeppers.SALTOTH_SK_SK_SK, Defaults.CONST_BYTES);
		public static final ConstantSalt SALTOTH_SKCTX_SKCTX_SKCTX = new ConstantSalt(ParametersAndPeppers.SALTOTH_SKCTX_SKCTX_SKCTX, Defaults.CONST_BYTES);
	}

	public static class Defaults {
		public static final int ITER = 600_000;
		public static final int DK_BYTES_LEN = 32;
		public static final Pbkdf2Algorithm PRF_ALG = Pbkdf2Algorithm.PBKDF2WithHmacSHA256;

		public static final int RAND_LEN_BYTES = 32;
		public static final int DER_LEN_BYTES = 32;
		public static final byte[] CONST_BYTES = "constant-salt-bytes".getBytes(StandardCharsets.UTF_8);
	}

	public static class Parameters {
		public static final Pbkdf2ParametersV1 STD_CB_NONE     = new Pbkdf2ParametersV1(Defaults.ITER, Defaults.DK_BYTES_LEN, Defaults.PRF_ALG, HashEncodeDecode.STD_CB_NONE);
		public static final Pbkdf2ParametersV1 STD_CB_SALT     = new Pbkdf2ParametersV1(Defaults.ITER, Defaults.DK_BYTES_LEN, Defaults.PRF_ALG, HashEncodeDecode.STD_CB_SALT);
		public static final Pbkdf2ParametersV1 STD_CB_OTH      = new Pbkdf2ParametersV1(Defaults.ITER, Defaults.DK_BYTES_LEN, Defaults.PRF_ALG, HashEncodeDecode.STD_CB_OTH);
		public static final Pbkdf2ParametersV1 STD_CB_SALT_OTH = new Pbkdf2ParametersV1(Defaults.ITER, Defaults.DK_BYTES_LEN, Defaults.PRF_ALG, HashEncodeDecode.STD_CB_SALT_OTH);
	}

	public static class PepperOptions {
		public static final MacAlgorithm MAC_ALG = MacAlgorithm.HmacSHA256;
		public static final Base64Util.EncoderDecoder ENC_DEC = Base64Util.STD;
	}

	public static class PreSalt {
		public static final SecretKey KEY = new SecretKeySpec("pre-salt-key".getBytes(StandardCharsets.UTF_8), PepperOptions.MAC_ALG.alg());

		public static final Mac NONE  = new Mac(null, new byte[0], new byte[0], PepperOptions.MAC_ALG, PepperOptions.ENC_DEC);
		public static final Mac CTX   = new Mac(null, new byte[7], new byte[3], PepperOptions.MAC_ALG, PepperOptions.ENC_DEC);
		public static final Mac SK    = new Mac(KEY,  new byte[0], new byte[0], PepperOptions.MAC_ALG, PepperOptions.ENC_DEC);
		public static final Mac SKCTX = new Mac(KEY,  new byte[3], new byte[2], PepperOptions.MAC_ALG, PepperOptions.ENC_DEC);
	}

	public static class PreHash {
		public static final SecretKey KEY = new SecretKeySpec("pre-hash-key".getBytes(StandardCharsets.UTF_8), PepperOptions.MAC_ALG.alg());

		public static final Mac NONE  = new Mac(null, new byte[0], new byte[0], PepperOptions.MAC_ALG, PepperOptions.ENC_DEC);
		public static final Mac CTX   = new Mac(null, new byte[7], new byte[3], PepperOptions.MAC_ALG, PepperOptions.ENC_DEC);
		public static final Mac SK    = new Mac(KEY,  new byte[0], new byte[0], PepperOptions.MAC_ALG, PepperOptions.ENC_DEC);
		public static final Mac SKCTX = new Mac(KEY,  new byte[3], new byte[2], PepperOptions.MAC_ALG, PepperOptions.ENC_DEC);
	}

	public static class PostHash {
		public static final SecretKey KEY = new SecretKeySpec("post-hash-key".getBytes(StandardCharsets.UTF_8), PepperOptions.MAC_ALG.alg());

		public static final Mac NONE  = new Mac(null, new byte[0], new byte[0], PepperOptions.MAC_ALG, PepperOptions.ENC_DEC);
		public static final Mac CTX   = new Mac(null, new byte[7], new byte[3], PepperOptions.MAC_ALG, PepperOptions.ENC_DEC);
		public static final Mac SK    = new Mac(KEY,  new byte[0], new byte[0], PepperOptions.MAC_ALG, PepperOptions.ENC_DEC);
		public static final Mac SKCTX = new Mac(KEY,  new byte[3], new byte[2], PepperOptions.MAC_ALG, PepperOptions.ENC_DEC);
	}

	// 125 Tuples of Peppers => PeppperPreSalt{NULL,NONE,CTX,SK,SKCTX} x PeppperPreHash{NULL,NONE,CTX,SK,SKCTX} x PeppperPostHash{NULL,NONE,CTX,SK,SKCTX})
	public static class Peppers {
		public static final Macs NULL_NULL_NULL    = new Macs(new Mac.PepperPreSalt(null),          new Mac.PepperPreHash(null),          new Mac.PepperPostHash(null));
		public static final Macs NONE_NONE_NONE    = new Macs(new Mac.PepperPreSalt(PreSalt.NONE),  new Mac.PepperPreHash(PreHash.NONE),  new Mac.PepperPostHash(PostHash.NONE));
		public static final Macs CTX_CTX_CTX       = new Macs(new Mac.PepperPreSalt(PreSalt.CTX),   new Mac.PepperPreHash(PreHash.CTX),   new Mac.PepperPostHash(PostHash.CTX));
		public static final Macs SK_SK_SK          = new Macs(new Mac.PepperPreSalt(PreSalt.SK),    new Mac.PepperPreHash(PreHash.SK),    new Mac.PepperPostHash(PostHash.SK));
		public static final Macs SKCTX_SKCTX_SKCTX = new Macs(new Mac.PepperPreSalt(PreSalt.SKCTX), new Mac.PepperPreHash(PreHash.SKCTX), new Mac.PepperPostHash(PostHash.SKCTX));
	}

	// Key+Context pairs for Macs
	public static class ParametersAndPeppers {
		public static final ParametersAndMacs NONE_NULL_NULL_NULL    = new ParametersAndMacs(Parameters.STD_CB_NONE, Peppers.NULL_NULL_NULL);
		public static final ParametersAndMacs NONE_NONE_NONE_NONE    = new ParametersAndMacs(Parameters.STD_CB_NONE, Peppers.NONE_NONE_NONE);
		public static final ParametersAndMacs NONE_CTX_CTX_CTX       = new ParametersAndMacs(Parameters.STD_CB_NONE, Peppers.CTX_CTX_CTX);
		public static final ParametersAndMacs NONE_SK_SK_SK          = new ParametersAndMacs(Parameters.STD_CB_NONE, Peppers.SK_SK_SK);
		public static final ParametersAndMacs NONE_SKCTX_SKCTX_SKCTX = new ParametersAndMacs(Parameters.STD_CB_NONE, Peppers.SKCTX_SKCTX_SKCTX);

		public static final ParametersAndMacs SALT_NULL_NULL_NULL    = new ParametersAndMacs(Parameters.STD_CB_SALT, Peppers.NULL_NULL_NULL);
		public static final ParametersAndMacs SALT_NONE_NONE_NONE    = new ParametersAndMacs(Parameters.STD_CB_SALT, Peppers.NONE_NONE_NONE);
		public static final ParametersAndMacs SALT_CTX_CTX_CTX       = new ParametersAndMacs(Parameters.STD_CB_SALT, Peppers.CTX_CTX_CTX);
		public static final ParametersAndMacs SALT_SK_SK_SK          = new ParametersAndMacs(Parameters.STD_CB_SALT, Peppers.SK_SK_SK);
		public static final ParametersAndMacs SALT_SKCTX_SKCTX_SKCTX = new ParametersAndMacs(Parameters.STD_CB_SALT, Peppers.SKCTX_SKCTX_SKCTX);

		public static final ParametersAndMacs OTH_NULL_NULL_NULL    = new ParametersAndMacs(Parameters.STD_CB_OTH, Peppers.NULL_NULL_NULL);
		public static final ParametersAndMacs OTH_NONE_NONE_NONE    = new ParametersAndMacs(Parameters.STD_CB_OTH, Peppers.NONE_NONE_NONE);
		public static final ParametersAndMacs OTH_CTX_CTX_CTX       = new ParametersAndMacs(Parameters.STD_CB_OTH, Peppers.CTX_CTX_CTX);
		public static final ParametersAndMacs OTH_SK_SK_SK          = new ParametersAndMacs(Parameters.STD_CB_OTH, Peppers.SK_SK_SK);
		public static final ParametersAndMacs OTH_SKCTX_SKCTX_SKCTX = new ParametersAndMacs(Parameters.STD_CB_OTH, Peppers.SKCTX_SKCTX_SKCTX);

		public static final ParametersAndMacs SALTOTH_NULL_NULL_NULL    = new ParametersAndMacs(Parameters.STD_CB_SALT_OTH, Peppers.NULL_NULL_NULL);
		public static final ParametersAndMacs SALTOTH_NONE_NONE_NONE    = new ParametersAndMacs(Parameters.STD_CB_SALT_OTH, Peppers.NONE_NONE_NONE);
		public static final ParametersAndMacs SALTOTH_CTX_CTX_CTX       = new ParametersAndMacs(Parameters.STD_CB_SALT_OTH, Peppers.CTX_CTX_CTX);
		public static final ParametersAndMacs SALTOTH_SK_SK_SK          = new ParametersAndMacs(Parameters.STD_CB_SALT_OTH, Peppers.SK_SK_SK);
		public static final ParametersAndMacs SALTOTH_SKCTX_SKCTX_SKCTX = new ParametersAndMacs(Parameters.STD_CB_SALT_OTH, Peppers.SKCTX_SKCTX_SKCTX);
	}
}
