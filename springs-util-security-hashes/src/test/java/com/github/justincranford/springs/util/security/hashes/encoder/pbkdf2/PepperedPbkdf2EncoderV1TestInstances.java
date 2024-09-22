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
		public static final RandomSalt VARS_CONS_NULL_NULL_NULL                   = new RandomSalt(ParametersAndPeppers.VARS_CONS_NULL_NULL_NULL,          Defaults.RAND_LEN_BYTES);
		public static final RandomSalt VARS_CONS_HPWDNOD_HPWDNOD_HPWDNOD          = new RandomSalt(ParametersAndPeppers.VARS_CONS_HPWDNOD_HPWDNOD_HPWDNOD,          Defaults.RAND_LEN_BYTES);
		public static final RandomSalt VARS_CONS_HPWDNODCTX_HPWDNODCTX_HPWDNODCTX = new RandomSalt(ParametersAndPeppers.VARS_CONS_HPWDNODCTX_HPWDNODCTX_HPWDNODCTX, Defaults.RAND_LEN_BYTES);
		public static final RandomSalt VARS_CONS_HKEYNOD_HKEYNOD_HKEYNOD          = new RandomSalt(ParametersAndPeppers.VARS_CONS_HKEYNOD_HKEYNOD_HKEYNOD,          Defaults.RAND_LEN_BYTES);
		public static final RandomSalt VARS_CONS_HKEYNODCTX_HKEYNODCTX_HKEYNODCTX = new RandomSalt(ParametersAndPeppers.VARS_CONS_HKEYNODCTX_HKEYNODCTX_HKEYNODCTX, Defaults.RAND_LEN_BYTES);
		public static final RandomSalt VARS_CONS_HPWDDER_HPWDDER_HPWDDER          = new RandomSalt(ParametersAndPeppers.VARS_CONS_HPWDDER_HPWDDER_HPWDDER,          Defaults.RAND_LEN_BYTES);
		public static final RandomSalt VARS_CONS_HPWDDERCTX_HPWDDERCTX_HPWDDERCTX = new RandomSalt(ParametersAndPeppers.VARS_CONS_HPWDDERCTX_HPWDDERCTX_HPWDDERCTX, Defaults.RAND_LEN_BYTES);
		public static final RandomSalt VARS_CONS_HKEYDER_HKEYDER_HKEYDER          = new RandomSalt(ParametersAndPeppers.VARS_CONS_HKEYDER_HKEYDER_HKEYDER,          Defaults.RAND_LEN_BYTES);
		public static final RandomSalt VARS_CONS_HKEYDERCTX_HKEYDERCTX_HKEYDERCTX = new RandomSalt(ParametersAndPeppers.VARS_CONS_HKEYDERCTX_HKEYDERCTX_HKEYDERCTX, Defaults.RAND_LEN_BYTES);
		public static final RandomSalt VARS_CONS_CPWDDER_CPWDDER_CPWDDER          = new RandomSalt(ParametersAndPeppers.VARS_CONS_CPWDDER_CPWDDER_CPWDDER,          Defaults.RAND_LEN_BYTES);
		public static final RandomSalt VARS_CONS_CPWDDERCTX_CPWDDERCTX_CPWDDERCTX = new RandomSalt(ParametersAndPeppers.VARS_CONS_CPWDDERCTX_CPWDDERCTX_CPWDDERCTX, Defaults.RAND_LEN_BYTES);
		public static final RandomSalt VARS_CONS_CKEYDER_CKEYDER_CKEYDER          = new RandomSalt(ParametersAndPeppers.VARS_CONS_CKEYDER_CKEYDER_CKEYDER,          Defaults.RAND_LEN_BYTES);
		public static final RandomSalt VARS_CONS_CKEYDERCTX_CKEYDERCTX_CKEYDERCTX = new RandomSalt(ParametersAndPeppers.VARS_CONS_CKEYDERCTX_CKEYDERCTX_CKEYDERCTX, Defaults.RAND_LEN_BYTES);

		public static final RandomSalt VARS_NULL_NULL_NULL                        = new RandomSalt(ParametersAndPeppers.VARS_NULL_NULL_NULL,               Defaults.RAND_LEN_BYTES);
		public static final RandomSalt VARS_HPWDNOD_HPWDNOD_HPWDNOD               = new RandomSalt(ParametersAndPeppers.VARS_HPWDNOD_HPWDNOD_HPWDNOD,               Defaults.RAND_LEN_BYTES);
		public static final RandomSalt VARS_HPWDNODCTX_HPWDNODCTX_HPWDNODCTX      = new RandomSalt(ParametersAndPeppers.VARS_HPWDNODCTX_HPWDNODCTX_HPWDNODCTX,      Defaults.RAND_LEN_BYTES);
		public static final RandomSalt VARS_HKEYNOD_HKEYNOD_HKEYNOD               = new RandomSalt(ParametersAndPeppers.VARS_HKEYNOD_HKEYNOD_HKEYNOD,               Defaults.RAND_LEN_BYTES);
		public static final RandomSalt VARS_HKEYNODCTX_HKEYNODCTX_HKEYNODCTX      = new RandomSalt(ParametersAndPeppers.VARS_HKEYNODCTX_HKEYNODCTX_HKEYNODCTX,      Defaults.RAND_LEN_BYTES);
		public static final RandomSalt VARS_HPWDDER_HPWDDER_HPWDDER               = new RandomSalt(ParametersAndPeppers.VARS_HPWDDER_HPWDDER_HPWDDER,               Defaults.RAND_LEN_BYTES);
		public static final RandomSalt VARS_HPWDDERCTX_HPWDDERCTX_HPWDDERCTX      = new RandomSalt(ParametersAndPeppers.VARS_HPWDDERCTX_HPWDDERCTX_HPWDDERCTX,      Defaults.RAND_LEN_BYTES);
		public static final RandomSalt VARS_HKEYDER_HKEYDER_HKEYDER               = new RandomSalt(ParametersAndPeppers.VARS_HKEYDER_HKEYDER_HKEYDER,               Defaults.RAND_LEN_BYTES);
		public static final RandomSalt VARS_HKEYDERCTX_HKEYDERCTX_HKEYDERCTX      = new RandomSalt(ParametersAndPeppers.VARS_HKEYDERCTX_HKEYDERCTX_HKEYDERCTX,      Defaults.RAND_LEN_BYTES);
		public static final RandomSalt VARS_CPWDDER_CPWDDER_CPWDDER               = new RandomSalt(ParametersAndPeppers.VARS_CPWDDER_CPWDDER_CPWDDER,               Defaults.RAND_LEN_BYTES);
		public static final RandomSalt VARS_CPWDDERCTX_CPWDDERCTX_CPWDDERCTX      = new RandomSalt(ParametersAndPeppers.VARS_CPWDDERCTX_CPWDDERCTX_CPWDDERCTX,      Defaults.RAND_LEN_BYTES);
		public static final RandomSalt VARS_CKEYDER_CKEYDER_CKEYDER               = new RandomSalt(ParametersAndPeppers.VARS_CKEYDER_CKEYDER_CKEYDER,               Defaults.RAND_LEN_BYTES);
		public static final RandomSalt VARS_CKEYDERCTX_CKEYDERCTX_CKEYDERCTX      = new RandomSalt(ParametersAndPeppers.VARS_CKEYDERCTX_CKEYDERCTX_CKEYDERCTX,      Defaults.RAND_LEN_BYTES);
	}

	public static final class Derived {
//		public static final DerivedSalt VARS_CONS_NULL_NULL_NULL                   = new DerivedSalt(ParametersAndPeppers.VARS_CONS_NULL_NULL_NULL, Defaults.DER_LEN_BYTES);
		public static final DerivedSalt VARS_CONS_HPWDNOD_HPWDNOD_HPWDNOD          = new DerivedSalt(ParametersAndPeppers.VARS_CONS_HPWDNOD_HPWDNOD_HPWDNOD,          Defaults.DER_LEN_BYTES);
		public static final DerivedSalt VARS_CONS_HPWDNODCTX_HPWDNODCTX_HPWDNODCTX = new DerivedSalt(ParametersAndPeppers.VARS_CONS_HPWDNODCTX_HPWDNODCTX_HPWDNODCTX, Defaults.DER_LEN_BYTES);
		public static final DerivedSalt VARS_CONS_HKEYNOD_HKEYNOD_HKEYNOD          = new DerivedSalt(ParametersAndPeppers.VARS_CONS_HKEYNOD_HKEYNOD_HKEYNOD,          Defaults.DER_LEN_BYTES);
		public static final DerivedSalt VARS_CONS_HKEYNODCTX_HKEYNODCTX_HKEYNODCTX = new DerivedSalt(ParametersAndPeppers.VARS_CONS_HKEYNODCTX_HKEYNODCTX_HKEYNODCTX, Defaults.DER_LEN_BYTES);
		public static final DerivedSalt VARS_CONS_HPWDDER_HPWDDER_HPWDDER          = new DerivedSalt(ParametersAndPeppers.VARS_CONS_HPWDDER_HPWDDER_HPWDDER,          Defaults.DER_LEN_BYTES);
		public static final DerivedSalt VARS_CONS_HPWDDERCTX_HPWDDERCTX_HPWDDERCTX = new DerivedSalt(ParametersAndPeppers.VARS_CONS_HPWDDERCTX_HPWDDERCTX_HPWDDERCTX, Defaults.DER_LEN_BYTES);
		public static final DerivedSalt VARS_CONS_HKEYDER_HKEYDER_HKEYDER          = new DerivedSalt(ParametersAndPeppers.VARS_CONS_HKEYDER_HKEYDER_HKEYDER,          Defaults.DER_LEN_BYTES);
		public static final DerivedSalt VARS_CONS_HKEYDERCTX_HKEYDERCTX_HKEYDERCTX = new DerivedSalt(ParametersAndPeppers.VARS_CONS_HKEYDERCTX_HKEYDERCTX_HKEYDERCTX, Defaults.DER_LEN_BYTES);
		public static final DerivedSalt VARS_CONS_CPWDDER_CPWDDER_CPWDDER          = new DerivedSalt(ParametersAndPeppers.VARS_CONS_CPWDDER_CPWDDER_CPWDDER,          Defaults.DER_LEN_BYTES);
		public static final DerivedSalt VARS_CONS_CPWDDERCTX_CPWDDERCTX_CPWDDERCTX = new DerivedSalt(ParametersAndPeppers.VARS_CONS_CPWDDERCTX_CPWDDERCTX_CPWDDERCTX, Defaults.DER_LEN_BYTES);
		public static final DerivedSalt VARS_CONS_CKEYDER_CKEYDER_CKEYDER          = new DerivedSalt(ParametersAndPeppers.VARS_CONS_CKEYDER_CKEYDER_CKEYDER,          Defaults.DER_LEN_BYTES);
		public static final DerivedSalt VARS_CONS_CKEYDERCTX_CKEYDERCTX_CKEYDERCTX = new DerivedSalt(ParametersAndPeppers.VARS_CONS_CKEYDERCTX_CKEYDERCTX_CKEYDERCTX, Defaults.DER_LEN_BYTES);

//		public static final DerivedSalt VARS_NULL_NULL_NULL                        = new DerivedSalt(ParametersAndPeppers.VARS_NULL_NULL_NULL, Defaults.DER_LEN_BYTES);
		public static final DerivedSalt VARS_HPWDNOD_HPWDNOD_HPWDNOD               = new DerivedSalt(ParametersAndPeppers.VARS_HPWDNOD_HPWDNOD_HPWDNOD,          Defaults.DER_LEN_BYTES);
		public static final DerivedSalt VARS_HPWDNODCTX_HPWDNODCTX_HPWDNODCTX      = new DerivedSalt(ParametersAndPeppers.VARS_HPWDNODCTX_HPWDNODCTX_HPWDNODCTX, Defaults.DER_LEN_BYTES);
		public static final DerivedSalt VARS_HKEYNOD_HKEYNOD_HKEYNOD               = new DerivedSalt(ParametersAndPeppers.VARS_HKEYNOD_HKEYNOD_HKEYNOD,          Defaults.DER_LEN_BYTES);
		public static final DerivedSalt VARS_HKEYNODCTX_HKEYNODCTX_HKEYNODCTX      = new DerivedSalt(ParametersAndPeppers.VARS_HKEYNODCTX_HKEYNODCTX_HKEYNODCTX, Defaults.DER_LEN_BYTES);
		public static final DerivedSalt VARS_HPWDDER_HPWDDER_HPWDDER               = new DerivedSalt(ParametersAndPeppers.VARS_HPWDDER_HPWDDER_HPWDDER,          Defaults.DER_LEN_BYTES);
		public static final DerivedSalt VARS_HPWDDERCTX_HPWDDERCTX_HPWDDERCTX      = new DerivedSalt(ParametersAndPeppers.VARS_HPWDDERCTX_HPWDDERCTX_HPWDDERCTX, Defaults.DER_LEN_BYTES);
		public static final DerivedSalt VARS_HKEYDER_HKEYDER_HKEYDER               = new DerivedSalt(ParametersAndPeppers.VARS_HKEYDER_HKEYDER_HKEYDER,          Defaults.DER_LEN_BYTES);
		public static final DerivedSalt VARS_HKEYDERCTX_HKEYDERCTX_HKEYDERCTX      = new DerivedSalt(ParametersAndPeppers.VARS_HKEYDERCTX_HKEYDERCTX_HKEYDERCTX, Defaults.DER_LEN_BYTES);
		public static final DerivedSalt VARS_CPWDDER_CPWDDER_CPWDDER               = new DerivedSalt(ParametersAndPeppers.VARS_CPWDDER_CPWDDER_CPWDDER,          Defaults.DER_LEN_BYTES);
		public static final DerivedSalt VARS_CPWDDERCTX_CPWDDERCTX_CPWDDERCTX      = new DerivedSalt(ParametersAndPeppers.VARS_CPWDDERCTX_CPWDDERCTX_CPWDDERCTX, Defaults.DER_LEN_BYTES);
		public static final DerivedSalt VARS_CKEYDER_CKEYDER_CKEYDER               = new DerivedSalt(ParametersAndPeppers.VARS_CKEYDER_CKEYDER_CKEYDER,          Defaults.DER_LEN_BYTES);
		public static final DerivedSalt VARS_CKEYDERCTX_CKEYDERCTX_CKEYDERCTX      = new DerivedSalt(ParametersAndPeppers.VARS_CKEYDERCTX_CKEYDERCTX_CKEYDERCTX, Defaults.DER_LEN_BYTES);

//		public static final DerivedSalt CONS_NULL_NULL_NULL                        = new DerivedSalt(ParametersAndPeppers.CONS_NULL_NULL_NULL, Defaults.DER_LEN_BYTES);
		public static final DerivedSalt CONS_HPWDNOD_HPWDNOD_HPWDNOD               = new DerivedSalt(ParametersAndPeppers.CONS_HPWDNOD_HPWDNOD_HPWDNOD,          Defaults.DER_LEN_BYTES);
		public static final DerivedSalt CONS_HPWDNODCTX_HPWDNODCTX_HPWDNODCTX      = new DerivedSalt(ParametersAndPeppers.CONS_HPWDNODCTX_HPWDNODCTX_HPWDNODCTX, Defaults.DER_LEN_BYTES);
		public static final DerivedSalt CONS_HKEYNOD_HKEYNOD_HKEYNOD               = new DerivedSalt(ParametersAndPeppers.CONS_HKEYNOD_HKEYNOD_HKEYNOD,          Defaults.DER_LEN_BYTES);
		public static final DerivedSalt CONS_HKEYNODCTX_HKEYNODCTX_HKEYNODCTX      = new DerivedSalt(ParametersAndPeppers.CONS_HKEYNODCTX_HKEYNODCTX_HKEYNODCTX, Defaults.DER_LEN_BYTES);
		public static final DerivedSalt CONS_HPWDDER_HPWDDER_HPWDDER               = new DerivedSalt(ParametersAndPeppers.CONS_HPWDDER_HPWDDER_HPWDDER,          Defaults.DER_LEN_BYTES);
		public static final DerivedSalt CONS_HPWDDERCTX_HPWDDERCTX_HPWDDERCTX      = new DerivedSalt(ParametersAndPeppers.CONS_HPWDDERCTX_HPWDDERCTX_HPWDDERCTX, Defaults.DER_LEN_BYTES);
		public static final DerivedSalt CONS_HKEYDER_HKEYDER_HKEYDER               = new DerivedSalt(ParametersAndPeppers.CONS_HKEYDER_HKEYDER_HKEYDER,          Defaults.DER_LEN_BYTES);
		public static final DerivedSalt CONS_HKEYDERCTX_HKEYDERCTX_HKEYDERCTX      = new DerivedSalt(ParametersAndPeppers.CONS_HKEYDERCTX_HKEYDERCTX_HKEYDERCTX, Defaults.DER_LEN_BYTES);
		public static final DerivedSalt CONS_CPWDDER_CPWDDER_CPWDDER               = new DerivedSalt(ParametersAndPeppers.CONS_CPWDDER_CPWDDER_CPWDDER,          Defaults.DER_LEN_BYTES);
		public static final DerivedSalt CONS_CPWDDERCTX_CPWDDERCTX_CPWDDERCTX      = new DerivedSalt(ParametersAndPeppers.CONS_CPWDDERCTX_CPWDDERCTX_CPWDDERCTX, Defaults.DER_LEN_BYTES);
		public static final DerivedSalt CONS_CKEYDER_CKEYDER_CKEYDER               = new DerivedSalt(ParametersAndPeppers.CONS_CKEYDER_CKEYDER_CKEYDER,          Defaults.DER_LEN_BYTES);
		public static final DerivedSalt CONS_CKEYDERCTX_CKEYDERCTX_CKEYDERCTX      = new DerivedSalt(ParametersAndPeppers.CONS_CKEYDERCTX_CKEYDERCTX_CKEYDERCTX, Defaults.DER_LEN_BYTES);

//		public static final DerivedSalt NONE_NULL_NULL_NULL                        = new DerivedSalt(ParametersAndPeppers.NONE_NULL_NULL_NULL, Defaults.DER_LEN_BYTES);
		public static final DerivedSalt NONE_HPWDNOD_HPWDNOD_HPWDNOD               = new DerivedSalt(ParametersAndPeppers.NONE_HPWDNOD_HPWDNOD_HPWDNOD,          Defaults.DER_LEN_BYTES);
		public static final DerivedSalt NONE_HPWDNODCTX_HPWDNODCTX_HPWDNODCTX      = new DerivedSalt(ParametersAndPeppers.NONE_HPWDNODCTX_HPWDNODCTX_HPWDNODCTX, Defaults.DER_LEN_BYTES);
		public static final DerivedSalt NONE_HKEYNOD_HKEYNOD_HKEYNOD               = new DerivedSalt(ParametersAndPeppers.NONE_HKEYNOD_HKEYNOD_HKEYNOD,          Defaults.DER_LEN_BYTES);
		public static final DerivedSalt NONE_HKEYNODCTX_HKEYNODCTX_HKEYNODCTX      = new DerivedSalt(ParametersAndPeppers.NONE_HKEYNODCTX_HKEYNODCTX_HKEYNODCTX, Defaults.DER_LEN_BYTES);
		public static final DerivedSalt NONE_HPWDDER_HPWDDER_HPWDDER               = new DerivedSalt(ParametersAndPeppers.NONE_HPWDDER_HPWDDER_HPWDDER,          Defaults.DER_LEN_BYTES);
		public static final DerivedSalt NONE_HPWDDERCTX_HPWDDERCTX_HPWDDERCTX      = new DerivedSalt(ParametersAndPeppers.NONE_HPWDDERCTX_HPWDDERCTX_HPWDDERCTX, Defaults.DER_LEN_BYTES);
		public static final DerivedSalt NONE_HKEYDER_HKEYDER_HKEYDER               = new DerivedSalt(ParametersAndPeppers.NONE_HKEYDER_HKEYDER_HKEYDER,          Defaults.DER_LEN_BYTES);
		public static final DerivedSalt NONE_HKEYDERCTX_HKEYDERCTX_HKEYDERCTX      = new DerivedSalt(ParametersAndPeppers.NONE_HKEYDERCTX_HKEYDERCTX_HKEYDERCTX, Defaults.DER_LEN_BYTES);
		public static final DerivedSalt NONE_CPWDDER_CPWDDER_CPWDDER               = new DerivedSalt(ParametersAndPeppers.NONE_CPWDDER_CPWDDER_CPWDDER,          Defaults.DER_LEN_BYTES);
		public static final DerivedSalt NONE_CPWDDERCTX_CPWDDERCTX_CPWDDERCTX      = new DerivedSalt(ParametersAndPeppers.NONE_CPWDDERCTX_CPWDDERCTX_CPWDDERCTX, Defaults.DER_LEN_BYTES);
		public static final DerivedSalt NONE_CKEYDER_CKEYDER_CKEYDER               = new DerivedSalt(ParametersAndPeppers.NONE_CKEYDER_CKEYDER_CKEYDER,          Defaults.DER_LEN_BYTES);
		public static final DerivedSalt NONE_CKEYDERCTX_CKEYDERCTX_CKEYDERCTX      = new DerivedSalt(ParametersAndPeppers.NONE_CKEYDERCTX_CKEYDERCTX_CKEYDERCTX, Defaults.DER_LEN_BYTES);
	}

	public static final class Constant {
		public static final ConstantSalt VARS_CONS_NULL_NULL_NULL                   = new ConstantSalt(ParametersAndPeppers.VARS_CONS_NULL_NULL_NULL,                   Defaults.CONST_SALT_BYTES);
		public static final ConstantSalt VARS_CONS_HPWDNOD_HPWDNOD_HPWDNOD          = new ConstantSalt(ParametersAndPeppers.VARS_CONS_HPWDNOD_HPWDNOD_HPWDNOD,          Defaults.CONST_SALT_BYTES);
		public static final ConstantSalt VARS_CONS_HPWDNODCTX_HPWDNODCTX_HPWDNODCTX = new ConstantSalt(ParametersAndPeppers.VARS_CONS_HPWDNODCTX_HPWDNODCTX_HPWDNODCTX, Defaults.CONST_SALT_BYTES);
		public static final ConstantSalt VARS_CONS_HKEYNOD_HKEYNOD_HKEYNOD          = new ConstantSalt(ParametersAndPeppers.VARS_CONS_HKEYNOD_HKEYNOD_HKEYNOD,          Defaults.CONST_SALT_BYTES);
		public static final ConstantSalt VARS_CONS_HKEYNODCTX_HKEYNODCTX_HKEYNODCTX = new ConstantSalt(ParametersAndPeppers.VARS_CONS_HKEYNODCTX_HKEYNODCTX_HKEYNODCTX, Defaults.CONST_SALT_BYTES);
		public static final ConstantSalt VARS_CONS_HPWDDER_HPWDDER_HPWDDER          = new ConstantSalt(ParametersAndPeppers.VARS_CONS_HPWDDER_HPWDDER_HPWDDER,          Defaults.CONST_SALT_BYTES);
		public static final ConstantSalt VARS_CONS_HPWDDERCTX_HPWDDERCTX_HPWDDERCTX = new ConstantSalt(ParametersAndPeppers.VARS_CONS_HPWDDERCTX_HPWDDERCTX_HPWDDERCTX, Defaults.CONST_SALT_BYTES);
		public static final ConstantSalt VARS_CONS_HKEYDER_HKEYDER_HKEYDER          = new ConstantSalt(ParametersAndPeppers.VARS_CONS_HKEYDER_HKEYDER_HKEYDER,          Defaults.CONST_SALT_BYTES);
		public static final ConstantSalt VARS_CONS_HKEYDERCTX_HKEYDERCTX_HKEYDERCTX = new ConstantSalt(ParametersAndPeppers.VARS_CONS_HKEYDERCTX_HKEYDERCTX_HKEYDERCTX, Defaults.CONST_SALT_BYTES);
		public static final ConstantSalt VARS_CONS_CPWDDER_CPWDDER_CPWDDER          = new ConstantSalt(ParametersAndPeppers.VARS_CONS_CPWDDER_CPWDDER_CPWDDER,          Defaults.CONST_SALT_BYTES);
		public static final ConstantSalt VARS_CONS_CPWDDERCTX_CPWDDERCTX_CPWDDERCTX = new ConstantSalt(ParametersAndPeppers.VARS_CONS_CPWDDERCTX_CPWDDERCTX_CPWDDERCTX, Defaults.CONST_SALT_BYTES);
		public static final ConstantSalt VARS_CONS_CKEYDER_CKEYDER_CKEYDER          = new ConstantSalt(ParametersAndPeppers.VARS_CONS_CKEYDER_CKEYDER_CKEYDER,          Defaults.CONST_SALT_BYTES);
		public static final ConstantSalt VARS_CONS_CKEYDERCTX_CKEYDERCTX_CKEYDERCTX = new ConstantSalt(ParametersAndPeppers.VARS_CONS_CKEYDERCTX_CKEYDERCTX_CKEYDERCTX, Defaults.CONST_SALT_BYTES);

		public static final ConstantSalt VARS_NULL_NULL_NULL                        = new ConstantSalt(ParametersAndPeppers.VARS_NULL_NULL_NULL,                   Defaults.CONST_SALT_BYTES);
		public static final ConstantSalt VARS_HPWDNOD_HPWDNOD_HPWDNOD               = new ConstantSalt(ParametersAndPeppers.VARS_HPWDNOD_HPWDNOD_HPWDNOD,          Defaults.CONST_SALT_BYTES);
		public static final ConstantSalt VARS_HPWDNODCTX_HPWDNODCTX_HPWDNODCTX      = new ConstantSalt(ParametersAndPeppers.VARS_HPWDNODCTX_HPWDNODCTX_HPWDNODCTX, Defaults.CONST_SALT_BYTES);
		public static final ConstantSalt VARS_HKEYNOD_HKEYNOD_HKEYNOD               = new ConstantSalt(ParametersAndPeppers.VARS_HKEYNOD_HKEYNOD_HKEYNOD,          Defaults.CONST_SALT_BYTES);
		public static final ConstantSalt VARS_HKEYNODCTX_HKEYNODCTX_HKEYNODCTX      = new ConstantSalt(ParametersAndPeppers.VARS_HKEYNODCTX_HKEYNODCTX_HKEYNODCTX, Defaults.CONST_SALT_BYTES);
		public static final ConstantSalt VARS_HPWDDER_HPWDDER_HPWDDER               = new ConstantSalt(ParametersAndPeppers.VARS_HPWDDER_HPWDDER_HPWDDER,          Defaults.CONST_SALT_BYTES);
		public static final ConstantSalt VARS_HPWDDERCTX_HPWDDERCTX_HPWDDERCTX      = new ConstantSalt(ParametersAndPeppers.VARS_HPWDDERCTX_HPWDDERCTX_HPWDDERCTX, Defaults.CONST_SALT_BYTES);
		public static final ConstantSalt VARS_HKEYDER_HKEYDER_HKEYDER               = new ConstantSalt(ParametersAndPeppers.VARS_HKEYDER_HKEYDER_HKEYDER,          Defaults.CONST_SALT_BYTES);
		public static final ConstantSalt VARS_HKEYDERCTX_HKEYDERCTX_HKEYDERCTX      = new ConstantSalt(ParametersAndPeppers.VARS_HKEYDERCTX_HKEYDERCTX_HKEYDERCTX, Defaults.CONST_SALT_BYTES);
		public static final ConstantSalt VARS_CPWDDER_CPWDDER_CPWDDER               = new ConstantSalt(ParametersAndPeppers.VARS_CPWDDER_CPWDDER_CPWDDER,          Defaults.CONST_SALT_BYTES);
		public static final ConstantSalt VARS_CPWDDERCTX_CPWDDERCTX_CPWDDERCTX      = new ConstantSalt(ParametersAndPeppers.VARS_CPWDDERCTX_CPWDDERCTX_CPWDDERCTX, Defaults.CONST_SALT_BYTES);
		public static final ConstantSalt VARS_CKEYDER_CKEYDER_CKEYDER               = new ConstantSalt(ParametersAndPeppers.VARS_CKEYDER_CKEYDER_CKEYDER,          Defaults.CONST_SALT_BYTES);
		public static final ConstantSalt VARS_CKEYDERCTX_CKEYDERCTX_CKEYDERCTX      = new ConstantSalt(ParametersAndPeppers.VARS_CKEYDERCTX_CKEYDERCTX_CKEYDERCTX, Defaults.CONST_SALT_BYTES);

		public static final ConstantSalt CONS_NULL_NULL_NULL                        = new ConstantSalt(ParametersAndPeppers.CONS_NULL_NULL_NULL,                   Defaults.CONST_SALT_BYTES);
		public static final ConstantSalt CONS_HPWDNOD_HPWDNOD_HPWDNOD               = new ConstantSalt(ParametersAndPeppers.CONS_HPWDNOD_HPWDNOD_HPWDNOD,          Defaults.CONST_SALT_BYTES);
		public static final ConstantSalt CONS_HPWDNODCTX_HPWDNODCTX_HPWDNODCTX      = new ConstantSalt(ParametersAndPeppers.CONS_HPWDNODCTX_HPWDNODCTX_HPWDNODCTX, Defaults.CONST_SALT_BYTES);
		public static final ConstantSalt CONS_HKEYNOD_HKEYNOD_HKEYNOD               = new ConstantSalt(ParametersAndPeppers.CONS_HKEYNOD_HKEYNOD_HKEYNOD,          Defaults.CONST_SALT_BYTES);
		public static final ConstantSalt CONS_HKEYNODCTX_HKEYNODCTX_HKEYNODCTX      = new ConstantSalt(ParametersAndPeppers.CONS_HKEYNODCTX_HKEYNODCTX_HKEYNODCTX, Defaults.CONST_SALT_BYTES);
		public static final ConstantSalt CONS_HPWDDER_HPWDDER_HPWDDER               = new ConstantSalt(ParametersAndPeppers.CONS_HPWDDER_HPWDDER_HPWDDER,          Defaults.CONST_SALT_BYTES);
		public static final ConstantSalt CONS_HPWDDERCTX_HPWDDERCTX_HPWDDERCTX      = new ConstantSalt(ParametersAndPeppers.CONS_HPWDDERCTX_HPWDDERCTX_HPWDDERCTX, Defaults.CONST_SALT_BYTES);
		public static final ConstantSalt CONS_HKEYDER_HKEYDER_HKEYDER               = new ConstantSalt(ParametersAndPeppers.CONS_HKEYDER_HKEYDER_HKEYDER,          Defaults.CONST_SALT_BYTES);
		public static final ConstantSalt CONS_HKEYDERCTX_HKEYDERCTX_HKEYDERCTX      = new ConstantSalt(ParametersAndPeppers.CONS_HKEYDERCTX_HKEYDERCTX_HKEYDERCTX, Defaults.CONST_SALT_BYTES);
		public static final ConstantSalt CONS_CPWDDER_CPWDDER_CPWDDER               = new ConstantSalt(ParametersAndPeppers.CONS_CPWDDER_CPWDDER_CPWDDER,          Defaults.CONST_SALT_BYTES);
		public static final ConstantSalt CONS_CPWDDERCTX_CPWDDERCTX_CPWDDERCTX      = new ConstantSalt(ParametersAndPeppers.CONS_CPWDDERCTX_CPWDDERCTX_CPWDDERCTX, Defaults.CONST_SALT_BYTES);
		public static final ConstantSalt CONS_CKEYDER_CKEYDER_CKEYDER               = new ConstantSalt(ParametersAndPeppers.CONS_CKEYDER_CKEYDER_CKEYDER,          Defaults.CONST_SALT_BYTES);
		public static final ConstantSalt CONS_CKEYDERCTX_CKEYDERCTX_CKEYDERCTX      = new ConstantSalt(ParametersAndPeppers.CONS_CKEYDERCTX_CKEYDERCTX_CKEYDERCTX, Defaults.CONST_SALT_BYTES);

		public static final ConstantSalt NONE_NULL_NULL_NULL                        = new ConstantSalt(ParametersAndPeppers.NONE_NULL_NULL_NULL,                   Defaults.CONST_SALT_BYTES);
		public static final ConstantSalt NONE_HPWDNOD_HPWDNOD_HPWDNOD               = new ConstantSalt(ParametersAndPeppers.NONE_HPWDNOD_HPWDNOD_HPWDNOD,          Defaults.CONST_SALT_BYTES);
		public static final ConstantSalt NONE_HPWDNODCTX_HPWDNODCTX_HPWDNODCTX      = new ConstantSalt(ParametersAndPeppers.NONE_HPWDNODCTX_HPWDNODCTX_HPWDNODCTX, Defaults.CONST_SALT_BYTES);
		public static final ConstantSalt NONE_HKEYNOD_HKEYNOD_HKEYNOD               = new ConstantSalt(ParametersAndPeppers.NONE_HKEYNOD_HKEYNOD_HKEYNOD,          Defaults.CONST_SALT_BYTES);
		public static final ConstantSalt NONE_HKEYNODCTX_HKEYNODCTX_HKEYNODCTX      = new ConstantSalt(ParametersAndPeppers.NONE_HKEYNODCTX_HKEYNODCTX_HKEYNODCTX, Defaults.CONST_SALT_BYTES);
		public static final ConstantSalt NONE_HPWDDER_HPWDDER_HPWDDER               = new ConstantSalt(ParametersAndPeppers.NONE_HPWDDER_HPWDDER_HPWDDER,          Defaults.CONST_SALT_BYTES);
		public static final ConstantSalt NONE_HPWDDERCTX_HPWDDERCTX_HPWDDERCTX      = new ConstantSalt(ParametersAndPeppers.NONE_HPWDDERCTX_HPWDDERCTX_HPWDDERCTX, Defaults.CONST_SALT_BYTES);
		public static final ConstantSalt NONE_HKEYDER_HKEYDER_HKEYDER               = new ConstantSalt(ParametersAndPeppers.NONE_HKEYDER_HKEYDER_HKEYDER,          Defaults.CONST_SALT_BYTES);
		public static final ConstantSalt NONE_HKEYDERCTX_HKEYDERCTX_HKEYDERCTX      = new ConstantSalt(ParametersAndPeppers.NONE_HKEYDERCTX_HKEYDERCTX_HKEYDERCTX, Defaults.CONST_SALT_BYTES);
		public static final ConstantSalt NONE_CPWDDER_CPWDDER_CPWDDER               = new ConstantSalt(ParametersAndPeppers.NONE_CPWDDER_CPWDDER_CPWDDER,          Defaults.CONST_SALT_BYTES);
		public static final ConstantSalt NONE_CPWDDERCTX_CPWDDERCTX_CPWDDERCTX      = new ConstantSalt(ParametersAndPeppers.NONE_CPWDDERCTX_CPWDDERCTX_CPWDDERCTX, Defaults.CONST_SALT_BYTES);
		public static final ConstantSalt NONE_CKEYDER_CKEYDER_CKEYDER               = new ConstantSalt(ParametersAndPeppers.NONE_CKEYDER_CKEYDER_CKEYDER,          Defaults.CONST_SALT_BYTES);
		public static final ConstantSalt NONE_CKEYDERCTX_CKEYDERCTX_CKEYDERCTX      = new ConstantSalt(ParametersAndPeppers.NONE_CKEYDERCTX_CKEYDERCTX_CKEYDERCTX, Defaults.CONST_SALT_BYTES);
	}

	public static class Codec {
		public static final TextCodec TEXT = TextCodec.B64_STD;
		public static final String    OUTER = "|";
		public static final String    INNER = ":";

		public static final HashCodec NONE      = new HashCodec(TEXT, OUTER, INNER, Flags.NONE);
		public static final HashCodec VARS      = new HashCodec(TEXT, OUTER, INNER, Flags.VARS);
		public static final HashCodec CONS      = new HashCodec(TEXT, OUTER, INNER, Flags.CONS);
		public static final HashCodec VARS_CONS = new HashCodec(TEXT, OUTER, INNER, Flags.BOTH);
	}

	public static class Defaults {
		public static final Pbkdf2AlgorithmV1 PRF_ALG = Pbkdf2AlgorithmV1.PBKDF2WithHmacSHA256;
		public static final int DK_BYTES_LEN = 32;
		public static final int ITER = 1; // OWASP recommends 600_000 in production

		public static final int RAND_LEN_BYTES = 32;
		public static final int DER_LEN_BYTES = 32;
		public static final byte[] CONST_SALT_BYTES = "constant-salt-bytes".getBytes(StandardCharsets.UTF_8);
	}

	public static class Constants {
		public static final Pbkdf2InputConstantsV1 VARS_CONS = new Pbkdf2InputConstantsV1(Defaults.PRF_ALG, Codec.VARS_CONS, Defaults.DK_BYTES_LEN, Defaults.ITER);
		public static final Pbkdf2InputConstantsV1 VARS      = new Pbkdf2InputConstantsV1(Defaults.PRF_ALG, Codec.VARS,      Defaults.DK_BYTES_LEN, Defaults.ITER);
		public static final Pbkdf2InputConstantsV1 CONS      = new Pbkdf2InputConstantsV1(Defaults.PRF_ALG, Codec.CONS,      Defaults.DK_BYTES_LEN, Defaults.ITER);
		public static final Pbkdf2InputConstantsV1 NONE      = new Pbkdf2InputConstantsV1(Defaults.PRF_ALG, Codec.NONE,      Defaults.DK_BYTES_LEN, Defaults.ITER);
	}

	public static class PepperOptions {
		public static final CmacAlgorithm CMAC_ALG = CmacAlgorithm.AesCmac128;
		public static final HmacAlgorithm HMAC_ALG = HmacAlgorithm.HmacSHA256;
		public static final DigestAlgorithm DER_ALG = DigestAlgorithm.SHA256;
		public static final Base64Util.EncoderDecoder ENC_DEC = Base64Util.URL;
	}

	public static class Key {
		public static final SecretKey CMAC = new SecretKeySpec(new byte[32], PepperOptions.CMAC_ALG.algorithm());
		public static final SecretKey HMAC = new SecretKeySpec("hmac-key".getBytes(StandardCharsets.UTF_8), PepperOptions.HMAC_ALG.algorithm());
		public static final SecretKey NULL = null;
	}

	public static class InputVariables {
		private static int i = 20;
		public static final HashPepperInputVariables NULL       = null;
		public static final HashPepperInputVariables HPWDNOD    = new HashPepperInputVariables(new Pepper(PepperOptions.HMAC_ALG, PepperOptions.ENC_DEC, Key.NULL, null,                  new byte[0], new byte[0]));
		public static final HashPepperInputVariables HPWDNODCTX = new HashPepperInputVariables(new Pepper(PepperOptions.HMAC_ALG, PepperOptions.ENC_DEC, Key.NULL, null,                  new byte[i++], new byte[i++]));
		public static final HashPepperInputVariables HKEYNOD    = new HashPepperInputVariables(new Pepper(PepperOptions.HMAC_ALG, PepperOptions.ENC_DEC, Key.HMAC, null,                  new byte[0], new byte[0]));
		public static final HashPepperInputVariables HKEYNODCTX = new HashPepperInputVariables(new Pepper(PepperOptions.HMAC_ALG, PepperOptions.ENC_DEC, Key.HMAC, null,                  new byte[i++], new byte[i++]));
		public static final HashPepperInputVariables HPWDDER    = new HashPepperInputVariables(new Pepper(PepperOptions.HMAC_ALG, PepperOptions.ENC_DEC, Key.NULL, PepperOptions.DER_ALG, new byte[0], new byte[0]));
		public static final HashPepperInputVariables HPWDDERCTX = new HashPepperInputVariables(new Pepper(PepperOptions.HMAC_ALG, PepperOptions.ENC_DEC, Key.NULL, PepperOptions.DER_ALG, new byte[i++], new byte[i++]));
		public static final HashPepperInputVariables HKEYDER    = new HashPepperInputVariables(new Pepper(PepperOptions.HMAC_ALG, PepperOptions.ENC_DEC, Key.HMAC, PepperOptions.DER_ALG, new byte[0], new byte[0]));
		public static final HashPepperInputVariables HKEYDERCTX = new HashPepperInputVariables(new Pepper(PepperOptions.HMAC_ALG, PepperOptions.ENC_DEC, Key.HMAC, PepperOptions.DER_ALG, new byte[i++], new byte[i++]));
		public static final HashPepperInputVariables CPWDDER    = new HashPepperInputVariables(new Pepper(PepperOptions.CMAC_ALG, PepperOptions.ENC_DEC, Key.NULL, PepperOptions.DER_ALG, new byte[0], new byte[0]));
		public static final HashPepperInputVariables CPWDDERCTX = new HashPepperInputVariables(new Pepper(PepperOptions.CMAC_ALG, PepperOptions.ENC_DEC, Key.NULL, PepperOptions.DER_ALG, new byte[i++], new byte[i++]));
		public static final HashPepperInputVariables CKEYDER    = new HashPepperInputVariables(new Pepper(PepperOptions.CMAC_ALG, PepperOptions.ENC_DEC, Key.CMAC, PepperOptions.DER_ALG, new byte[0], new byte[0]));
		public static final HashPepperInputVariables CKEYDERCTX = new HashPepperInputVariables(new Pepper(PepperOptions.CMAC_ALG, PepperOptions.ENC_DEC, Key.CMAC, PepperOptions.DER_ALG, new byte[i++], new byte[i++]));
	}

	public static class PreHash {
		private static int i = 40;
		public static final HashPepperPreHash NULL       = null;
		public static final HashPepperPreHash HPWDNOD    = new HashPepperPreHash(new Pepper(PepperOptions.HMAC_ALG, PepperOptions.ENC_DEC, Key.NULL,  null,                  new byte[0], new byte[0]));
		public static final HashPepperPreHash HPWDNODCTX = new HashPepperPreHash(new Pepper(PepperOptions.HMAC_ALG, PepperOptions.ENC_DEC, Key.NULL,  null,                  new byte[i++], new byte[i++]));
		public static final HashPepperPreHash HKEYNOD    = new HashPepperPreHash(new Pepper(PepperOptions.HMAC_ALG, PepperOptions.ENC_DEC, Key.HMAC,  null,                  new byte[0], new byte[0]));
		public static final HashPepperPreHash HKEYNODCTX = new HashPepperPreHash(new Pepper(PepperOptions.HMAC_ALG, PepperOptions.ENC_DEC, Key.HMAC,  null,                  new byte[i++], new byte[i++]));
		public static final HashPepperPreHash HPWDDER    = new HashPepperPreHash(new Pepper(PepperOptions.HMAC_ALG, PepperOptions.ENC_DEC, Key.NULL,  PepperOptions.DER_ALG, new byte[0], new byte[0]));
		public static final HashPepperPreHash HPWDDERCTX = new HashPepperPreHash(new Pepper(PepperOptions.HMAC_ALG, PepperOptions.ENC_DEC, Key.NULL,  PepperOptions.DER_ALG, new byte[i++], new byte[i++]));
		public static final HashPepperPreHash HKEYDER    = new HashPepperPreHash(new Pepper(PepperOptions.HMAC_ALG, PepperOptions.ENC_DEC, Key.HMAC,  PepperOptions.DER_ALG, new byte[0], new byte[0]));
		public static final HashPepperPreHash HKEYDERCTX = new HashPepperPreHash(new Pepper(PepperOptions.HMAC_ALG, PepperOptions.ENC_DEC, Key.HMAC,  PepperOptions.DER_ALG, new byte[i++], new byte[i++]));
		public static final HashPepperPreHash CPWDDER    = new HashPepperPreHash(new Pepper(PepperOptions.CMAC_ALG, PepperOptions.ENC_DEC, Key.NULL,  PepperOptions.DER_ALG, new byte[0], new byte[0]));
		public static final HashPepperPreHash CPWDDERCTX = new HashPepperPreHash(new Pepper(PepperOptions.CMAC_ALG, PepperOptions.ENC_DEC, Key.NULL,  PepperOptions.DER_ALG, new byte[i++], new byte[i++]));
		public static final HashPepperPreHash CKEYDER    = new HashPepperPreHash(new Pepper(PepperOptions.CMAC_ALG, PepperOptions.ENC_DEC, Key.CMAC,  PepperOptions.DER_ALG, new byte[0], new byte[0]));
		public static final HashPepperPreHash CKEYDERCTX = new HashPepperPreHash(new Pepper(PepperOptions.CMAC_ALG, PepperOptions.ENC_DEC, Key.CMAC,  PepperOptions.DER_ALG, new byte[i++], new byte[i++]));
	}

	public static class PostHash {
		private static int i = 60;
		public static final HashPepperPostHash NULL       = null;
		public static final HashPepperPostHash HPWDNOD    = new HashPepperPostHash(new Pepper(PepperOptions.HMAC_ALG, PepperOptions.ENC_DEC, Key.NULL,  null,                  new byte[0], new byte[0]));
		public static final HashPepperPostHash HPWDNODCTX = new HashPepperPostHash(new Pepper(PepperOptions.HMAC_ALG, PepperOptions.ENC_DEC, Key.NULL,  null,                  new byte[i++], new byte[i++]));
		public static final HashPepperPostHash HKEYNOD    = new HashPepperPostHash(new Pepper(PepperOptions.HMAC_ALG, PepperOptions.ENC_DEC, Key.HMAC,  null,                  new byte[0], new byte[0]));
		public static final HashPepperPostHash HKEYNODCTX = new HashPepperPostHash(new Pepper(PepperOptions.HMAC_ALG, PepperOptions.ENC_DEC, Key.HMAC,  null,                  new byte[i++], new byte[i++]));
		public static final HashPepperPostHash HPWDDER    = new HashPepperPostHash(new Pepper(PepperOptions.HMAC_ALG, PepperOptions.ENC_DEC, Key.NULL,  PepperOptions.DER_ALG, new byte[0], new byte[0]));
		public static final HashPepperPostHash HPWDDERCTX = new HashPepperPostHash(new Pepper(PepperOptions.HMAC_ALG, PepperOptions.ENC_DEC, Key.NULL,  PepperOptions.DER_ALG, new byte[i++], new byte[i++]));
		public static final HashPepperPostHash HKEYDER    = new HashPepperPostHash(new Pepper(PepperOptions.HMAC_ALG, PepperOptions.ENC_DEC, Key.HMAC,  PepperOptions.DER_ALG, new byte[0], new byte[0]));
		public static final HashPepperPostHash HKEYDERCTX = new HashPepperPostHash(new Pepper(PepperOptions.HMAC_ALG, PepperOptions.ENC_DEC, Key.HMAC,  PepperOptions.DER_ALG, new byte[i++], new byte[i++]));
		public static final HashPepperPostHash CPWDDER    = new HashPepperPostHash(new Pepper(PepperOptions.CMAC_ALG, PepperOptions.ENC_DEC, Key.NULL,  PepperOptions.DER_ALG, new byte[0], new byte[0]));
		public static final HashPepperPostHash CPWDDERCTX = new HashPepperPostHash(new Pepper(PepperOptions.CMAC_ALG, PepperOptions.ENC_DEC, Key.NULL,  PepperOptions.DER_ALG, new byte[i++], new byte[i++]));
		public static final HashPepperPostHash CKEYDER    = new HashPepperPostHash(new Pepper(PepperOptions.CMAC_ALG, PepperOptions.ENC_DEC, Key.CMAC,  PepperOptions.DER_ALG, new byte[0], new byte[0]));
		public static final HashPepperPostHash CKEYDERCTX = new HashPepperPostHash(new Pepper(PepperOptions.CMAC_ALG, PepperOptions.ENC_DEC, Key.CMAC,  PepperOptions.DER_ALG, new byte[i++], new byte[i++]));
	}

	// 125 Tuples of Peppers => PeppperPreSalt{NULL,NONE,CTX,SK,SKCTX} x PeppperPreHash{NULL,NONE,CTX,SK,SKCTX} x PeppperPostHash{NULL,NONE,CTX,SK,SKCTX})
	public static class Peppers {
		public static final HashPeppers NULL_NULL_NULL                   = new HashPeppers(InputVariables.NULL,    PreHash.NULL,    PostHash.NULL);
		public static final HashPeppers HPWDNOD_HPWDNOD_HPWDNOD          = new HashPeppers(InputVariables.HPWDNOD,    PreHash.HPWDNOD,    PostHash.HPWDNOD);
		public static final HashPeppers HPWDNODCTX_HPWDNODCTX_HPWDNODCTX = new HashPeppers(InputVariables.HPWDNODCTX, PreHash.HPWDNODCTX, PostHash.HPWDNODCTX);
		public static final HashPeppers HKEYNOD_HKEYNOD_HKEYNOD          = new HashPeppers(InputVariables.HKEYNOD,    PreHash.HKEYNOD,    PostHash.HKEYNOD);
		public static final HashPeppers HKEYNODCTX_HKEYNODCTX_HKEYNODCTX = new HashPeppers(InputVariables.HKEYNODCTX, PreHash.HKEYNODCTX, PostHash.HKEYNODCTX);
		public static final HashPeppers HPWDDER_HPWDDER_HPWDDER          = new HashPeppers(InputVariables.HPWDDER,    PreHash.HPWDDER,    PostHash.HPWDDER);
		public static final HashPeppers HPWDDERCTX_HPWDDERCTX_HPWDDERCTX = new HashPeppers(InputVariables.HPWDDERCTX, PreHash.HPWDDERCTX, PostHash.HPWDDERCTX);
		public static final HashPeppers HKEYDER_HKEYDER_HKEYDER          = new HashPeppers(InputVariables.HKEYDER,    PreHash.HKEYDER,    PostHash.HKEYDER);
		public static final HashPeppers HKEYDERCTX_HKEYDERCTX_HKEYDERCTX = new HashPeppers(InputVariables.HKEYDERCTX, PreHash.HKEYDERCTX, PostHash.HKEYDERCTX);
		public static final HashPeppers CPWDDER_CPWDDER_CPWDDER          = new HashPeppers(InputVariables.CPWDDER,    PreHash.CPWDDER,    PostHash.CPWDDER);
		public static final HashPeppers CPWDDERCTX_CPWDDERCTX_CPWDDERCTX = new HashPeppers(InputVariables.CPWDDERCTX, PreHash.CPWDDERCTX, PostHash.CPWDDERCTX);
		public static final HashPeppers CKEYDER_CKEYDER_CKEYDER          = new HashPeppers(InputVariables.CKEYDER,    PreHash.CKEYDER,    PostHash.CKEYDER);
		public static final HashPeppers CKEYDERCTX_CKEYDERCTX_CKEYDERCTX = new HashPeppers(InputVariables.CKEYDERCTX, PreHash.CKEYDERCTX, PostHash.CKEYDERCTX);
	}

	// Key+Context pairs for Macs
	public static class ParametersAndPeppers {
		public static final HashInputConstantsAndHashPeppers NONE_NULL_NULL_NULL                   = new HashInputConstantsAndHashPeppers(Constants.NONE, Peppers.NULL_NULL_NULL);
		public static final HashInputConstantsAndHashPeppers NONE_HPWDNOD_HPWDNOD_HPWDNOD          = new HashInputConstantsAndHashPeppers(Constants.NONE, Peppers.HPWDNOD_HPWDNOD_HPWDNOD);
		public static final HashInputConstantsAndHashPeppers NONE_HPWDNODCTX_HPWDNODCTX_HPWDNODCTX = new HashInputConstantsAndHashPeppers(Constants.NONE, Peppers.HPWDNODCTX_HPWDNODCTX_HPWDNODCTX);
		public static final HashInputConstantsAndHashPeppers NONE_HKEYNOD_HKEYNOD_HKEYNOD          = new HashInputConstantsAndHashPeppers(Constants.NONE, Peppers.HKEYNOD_HKEYNOD_HKEYNOD);
		public static final HashInputConstantsAndHashPeppers NONE_HKEYNODCTX_HKEYNODCTX_HKEYNODCTX = new HashInputConstantsAndHashPeppers(Constants.NONE, Peppers.HKEYNODCTX_HKEYNODCTX_HKEYNODCTX);
		public static final HashInputConstantsAndHashPeppers NONE_HPWDDER_HPWDDER_HPWDDER          = new HashInputConstantsAndHashPeppers(Constants.NONE, Peppers.HPWDDER_HPWDDER_HPWDDER);
		public static final HashInputConstantsAndHashPeppers NONE_HPWDDERCTX_HPWDDERCTX_HPWDDERCTX = new HashInputConstantsAndHashPeppers(Constants.NONE, Peppers.HPWDDERCTX_HPWDDERCTX_HPWDDERCTX);
		public static final HashInputConstantsAndHashPeppers NONE_HKEYDER_HKEYDER_HKEYDER          = new HashInputConstantsAndHashPeppers(Constants.NONE, Peppers.HKEYDER_HKEYDER_HKEYDER);
		public static final HashInputConstantsAndHashPeppers NONE_HKEYDERCTX_HKEYDERCTX_HKEYDERCTX = new HashInputConstantsAndHashPeppers(Constants.NONE, Peppers.HKEYDERCTX_HKEYDERCTX_HKEYDERCTX);
		public static final HashInputConstantsAndHashPeppers NONE_CPWDDER_CPWDDER_CPWDDER          = new HashInputConstantsAndHashPeppers(Constants.NONE, Peppers.CPWDDER_CPWDDER_CPWDDER);
		public static final HashInputConstantsAndHashPeppers NONE_CPWDDERCTX_CPWDDERCTX_CPWDDERCTX = new HashInputConstantsAndHashPeppers(Constants.NONE, Peppers.CPWDDERCTX_CPWDDERCTX_CPWDDERCTX);
		public static final HashInputConstantsAndHashPeppers NONE_CKEYDER_CKEYDER_CKEYDER          = new HashInputConstantsAndHashPeppers(Constants.NONE, Peppers.CKEYDER_CKEYDER_CKEYDER);
		public static final HashInputConstantsAndHashPeppers NONE_CKEYDERCTX_CKEYDERCTX_CKEYDERCTX = new HashInputConstantsAndHashPeppers(Constants.NONE, Peppers.CKEYDERCTX_CKEYDERCTX_CKEYDERCTX);

		public static final HashInputConstantsAndHashPeppers VARS_NULL_NULL_NULL                   = new HashInputConstantsAndHashPeppers(Constants.VARS, Peppers.NULL_NULL_NULL);
		public static final HashInputConstantsAndHashPeppers VARS_HPWDNOD_HPWDNOD_HPWDNOD          = new HashInputConstantsAndHashPeppers(Constants.VARS, Peppers.HPWDNOD_HPWDNOD_HPWDNOD);
		public static final HashInputConstantsAndHashPeppers VARS_HPWDNODCTX_HPWDNODCTX_HPWDNODCTX = new HashInputConstantsAndHashPeppers(Constants.VARS, Peppers.HPWDNODCTX_HPWDNODCTX_HPWDNODCTX);
		public static final HashInputConstantsAndHashPeppers VARS_HKEYNOD_HKEYNOD_HKEYNOD          = new HashInputConstantsAndHashPeppers(Constants.VARS, Peppers.HKEYNOD_HKEYNOD_HKEYNOD);
		public static final HashInputConstantsAndHashPeppers VARS_HKEYNODCTX_HKEYNODCTX_HKEYNODCTX = new HashInputConstantsAndHashPeppers(Constants.VARS, Peppers.HKEYNODCTX_HKEYNODCTX_HKEYNODCTX);
		public static final HashInputConstantsAndHashPeppers VARS_HPWDDER_HPWDDER_HPWDDER          = new HashInputConstantsAndHashPeppers(Constants.VARS, Peppers.HPWDDER_HPWDDER_HPWDDER);
		public static final HashInputConstantsAndHashPeppers VARS_HPWDDERCTX_HPWDDERCTX_HPWDDERCTX = new HashInputConstantsAndHashPeppers(Constants.VARS, Peppers.HPWDDERCTX_HPWDDERCTX_HPWDDERCTX);
		public static final HashInputConstantsAndHashPeppers VARS_HKEYDER_HKEYDER_HKEYDER          = new HashInputConstantsAndHashPeppers(Constants.VARS, Peppers.HKEYDER_HKEYDER_HKEYDER);
		public static final HashInputConstantsAndHashPeppers VARS_HKEYDERCTX_HKEYDERCTX_HKEYDERCTX = new HashInputConstantsAndHashPeppers(Constants.VARS, Peppers.HKEYDERCTX_HKEYDERCTX_HKEYDERCTX);
		public static final HashInputConstantsAndHashPeppers VARS_CPWDDER_CPWDDER_CPWDDER          = new HashInputConstantsAndHashPeppers(Constants.VARS, Peppers.CPWDDER_CPWDDER_CPWDDER);
		public static final HashInputConstantsAndHashPeppers VARS_CPWDDERCTX_CPWDDERCTX_CPWDDERCTX = new HashInputConstantsAndHashPeppers(Constants.VARS, Peppers.CPWDDERCTX_CPWDDERCTX_CPWDDERCTX);
		public static final HashInputConstantsAndHashPeppers VARS_CKEYDER_CKEYDER_CKEYDER          = new HashInputConstantsAndHashPeppers(Constants.VARS, Peppers.CKEYDER_CKEYDER_CKEYDER);
		public static final HashInputConstantsAndHashPeppers VARS_CKEYDERCTX_CKEYDERCTX_CKEYDERCTX = new HashInputConstantsAndHashPeppers(Constants.VARS, Peppers.CKEYDERCTX_CKEYDERCTX_CKEYDERCTX);

		public static final HashInputConstantsAndHashPeppers CONS_NULL_NULL_NULL                   = new HashInputConstantsAndHashPeppers(Constants.CONS, Peppers.NULL_NULL_NULL);
		public static final HashInputConstantsAndHashPeppers CONS_HPWDNOD_HPWDNOD_HPWDNOD          = new HashInputConstantsAndHashPeppers(Constants.CONS, Peppers.HPWDNOD_HPWDNOD_HPWDNOD);
		public static final HashInputConstantsAndHashPeppers CONS_HPWDNODCTX_HPWDNODCTX_HPWDNODCTX = new HashInputConstantsAndHashPeppers(Constants.CONS, Peppers.HPWDNODCTX_HPWDNODCTX_HPWDNODCTX);
		public static final HashInputConstantsAndHashPeppers CONS_HKEYNOD_HKEYNOD_HKEYNOD          = new HashInputConstantsAndHashPeppers(Constants.CONS, Peppers.HKEYNOD_HKEYNOD_HKEYNOD);
		public static final HashInputConstantsAndHashPeppers CONS_HKEYNODCTX_HKEYNODCTX_HKEYNODCTX = new HashInputConstantsAndHashPeppers(Constants.CONS, Peppers.HKEYNODCTX_HKEYNODCTX_HKEYNODCTX);
		public static final HashInputConstantsAndHashPeppers CONS_HPWDDER_HPWDDER_HPWDDER          = new HashInputConstantsAndHashPeppers(Constants.CONS, Peppers.HPWDDER_HPWDDER_HPWDDER);
		public static final HashInputConstantsAndHashPeppers CONS_HPWDDERCTX_HPWDDERCTX_HPWDDERCTX = new HashInputConstantsAndHashPeppers(Constants.CONS, Peppers.HPWDDERCTX_HPWDDERCTX_HPWDDERCTX);
		public static final HashInputConstantsAndHashPeppers CONS_HKEYDER_HKEYDER_HKEYDER          = new HashInputConstantsAndHashPeppers(Constants.CONS, Peppers.HKEYDER_HKEYDER_HKEYDER);
		public static final HashInputConstantsAndHashPeppers CONS_HKEYDERCTX_HKEYDERCTX_HKEYDERCTX = new HashInputConstantsAndHashPeppers(Constants.CONS, Peppers.HKEYDERCTX_HKEYDERCTX_HKEYDERCTX);
		public static final HashInputConstantsAndHashPeppers CONS_CPWDDER_CPWDDER_CPWDDER          = new HashInputConstantsAndHashPeppers(Constants.CONS, Peppers.CPWDDER_CPWDDER_CPWDDER);
		public static final HashInputConstantsAndHashPeppers CONS_CPWDDERCTX_CPWDDERCTX_CPWDDERCTX = new HashInputConstantsAndHashPeppers(Constants.CONS, Peppers.CPWDDERCTX_CPWDDERCTX_CPWDDERCTX);
		public static final HashInputConstantsAndHashPeppers CONS_CKEYDER_CKEYDER_CKEYDER          = new HashInputConstantsAndHashPeppers(Constants.CONS, Peppers.CKEYDER_CKEYDER_CKEYDER);
		public static final HashInputConstantsAndHashPeppers CONS_CKEYDERCTX_CKEYDERCTX_CKEYDERCTX = new HashInputConstantsAndHashPeppers(Constants.CONS, Peppers.CKEYDERCTX_CKEYDERCTX_CKEYDERCTX);

		public static final HashInputConstantsAndHashPeppers VARS_CONS_NULL_NULL_NULL                   = new HashInputConstantsAndHashPeppers(Constants.VARS_CONS, Peppers.NULL_NULL_NULL);
		public static final HashInputConstantsAndHashPeppers VARS_CONS_HPWDNOD_HPWDNOD_HPWDNOD          = new HashInputConstantsAndHashPeppers(Constants.VARS_CONS, Peppers.HPWDNOD_HPWDNOD_HPWDNOD);
		public static final HashInputConstantsAndHashPeppers VARS_CONS_HPWDNODCTX_HPWDNODCTX_HPWDNODCTX = new HashInputConstantsAndHashPeppers(Constants.VARS_CONS, Peppers.HPWDNODCTX_HPWDNODCTX_HPWDNODCTX);
		public static final HashInputConstantsAndHashPeppers VARS_CONS_HKEYNOD_HKEYNOD_HKEYNOD          = new HashInputConstantsAndHashPeppers(Constants.VARS_CONS, Peppers.HKEYNOD_HKEYNOD_HKEYNOD);
		public static final HashInputConstantsAndHashPeppers VARS_CONS_HKEYNODCTX_HKEYNODCTX_HKEYNODCTX = new HashInputConstantsAndHashPeppers(Constants.VARS_CONS, Peppers.HKEYNODCTX_HKEYNODCTX_HKEYNODCTX);
		public static final HashInputConstantsAndHashPeppers VARS_CONS_HPWDDER_HPWDDER_HPWDDER          = new HashInputConstantsAndHashPeppers(Constants.VARS_CONS, Peppers.HPWDDER_HPWDDER_HPWDDER);
		public static final HashInputConstantsAndHashPeppers VARS_CONS_HPWDDERCTX_HPWDDERCTX_HPWDDERCTX = new HashInputConstantsAndHashPeppers(Constants.VARS_CONS, Peppers.HPWDDERCTX_HPWDDERCTX_HPWDDERCTX);
		public static final HashInputConstantsAndHashPeppers VARS_CONS_HKEYDER_HKEYDER_HKEYDER          = new HashInputConstantsAndHashPeppers(Constants.VARS_CONS, Peppers.HKEYDER_HKEYDER_HKEYDER);
		public static final HashInputConstantsAndHashPeppers VARS_CONS_HKEYDERCTX_HKEYDERCTX_HKEYDERCTX = new HashInputConstantsAndHashPeppers(Constants.VARS_CONS, Peppers.HKEYDERCTX_HKEYDERCTX_HKEYDERCTX);
		public static final HashInputConstantsAndHashPeppers VARS_CONS_CPWDDER_CPWDDER_CPWDDER          = new HashInputConstantsAndHashPeppers(Constants.VARS_CONS, Peppers.CPWDDER_CPWDDER_CPWDDER);
		public static final HashInputConstantsAndHashPeppers VARS_CONS_CPWDDERCTX_CPWDDERCTX_CPWDDERCTX = new HashInputConstantsAndHashPeppers(Constants.VARS_CONS, Peppers.CPWDDERCTX_CPWDDERCTX_CPWDDERCTX);
		public static final HashInputConstantsAndHashPeppers VARS_CONS_CKEYDER_CKEYDER_CKEYDER          = new HashInputConstantsAndHashPeppers(Constants.VARS_CONS, Peppers.CKEYDER_CKEYDER_CKEYDER);
		public static final HashInputConstantsAndHashPeppers VARS_CONS_CKEYDERCTX_CKEYDERCTX_CKEYDERCTX = new HashInputConstantsAndHashPeppers(Constants.VARS_CONS, Peppers.CKEYDERCTX_CKEYDERCTX_CKEYDERCTX);
	}
}
