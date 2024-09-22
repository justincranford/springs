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
		public static final RandomSalt VARS_CONS_NULL_NULL_NULL          = new RandomSalt(ParametersAndPeppers.VARS_CONS_NULL_NULL_NULL,                Defaults.RAND_LEN_BYTES);
		public static final RandomSalt VARS_CONS_NONE_NONE_NONE          = new RandomSalt(ParametersAndPeppers.VARS_CONS_NONE_NONE_NONE,                Defaults.RAND_LEN_BYTES);
		public static final RandomSalt VARS_CONS_CTX_CTX_CTX             = new RandomSalt(ParametersAndPeppers.VARS_CONS_CTX_CTX_CTX,                   Defaults.RAND_LEN_BYTES);
		public static final RandomSalt VARS_CONS_HPWD_HPWD_HPWD          = new RandomSalt(ParametersAndPeppers.VARS_CONS_HPWD_HPWD_HPWD,          Defaults.RAND_LEN_BYTES);
		public static final RandomSalt VARS_CONS_HPWDCTX_HPWDCTX_HPWDCTX = new RandomSalt(ParametersAndPeppers.VARS_CONS_HPWDCTX_HPWDCTX_HPWDCTX, Defaults.RAND_LEN_BYTES);
		public static final RandomSalt VARS_CONS_HKEY_HKEY_HKEY          = new RandomSalt(ParametersAndPeppers.VARS_CONS_HKEY_HKEY_HKEY,          Defaults.RAND_LEN_BYTES);
		public static final RandomSalt VARS_CONS_HKEYCTX_HKEYCTX_HKEYCTX = new RandomSalt(ParametersAndPeppers.VARS_CONS_HKEYCTX_HKEYCTX_HKEYCTX, Defaults.RAND_LEN_BYTES);
		public static final RandomSalt VARS_CONS_CPWD_CPWD_CPWD          = new RandomSalt(ParametersAndPeppers.VARS_CONS_CPWD_CPWD_CPWD,          Defaults.RAND_LEN_BYTES);
		public static final RandomSalt VARS_CONS_CPWDCTX_CPWDCTX_CPWDCTX = new RandomSalt(ParametersAndPeppers.VARS_CONS_CPWDCTX_CPWDCTX_CPWDCTX, Defaults.RAND_LEN_BYTES);
		public static final RandomSalt VARS_CONS_CKEY_CKEY_CKEY          = new RandomSalt(ParametersAndPeppers.VARS_CONS_CKEY_CKEY_CKEY,          Defaults.RAND_LEN_BYTES);
		public static final RandomSalt VARS_CONS_CKEYCTX_CKEYCTX_CKEYCTX = new RandomSalt(ParametersAndPeppers.VARS_CONS_CKEYCTX_CKEYCTX_CKEYCTX, Defaults.RAND_LEN_BYTES);

		public static final RandomSalt VARS_NULL_NULL_NULL               = new RandomSalt(ParametersAndPeppers.VARS_NULL_NULL_NULL,                     Defaults.RAND_LEN_BYTES);
		public static final RandomSalt VARS_NONE_NONE_NONE               = new RandomSalt(ParametersAndPeppers.VARS_NONE_NONE_NONE,                     Defaults.RAND_LEN_BYTES);
		public static final RandomSalt VARS_CTX_CTX_CTX                  = new RandomSalt(ParametersAndPeppers.VARS_CTX_CTX_CTX,                        Defaults.RAND_LEN_BYTES);
		public static final RandomSalt VARS_HPWD_HPWD_HPWD               = new RandomSalt(ParametersAndPeppers.VARS_HPWD_HPWD_HPWD,               Defaults.RAND_LEN_BYTES);
		public static final RandomSalt VARS_HPWDCTX_HPWDCTX_HPWDCTX      = new RandomSalt(ParametersAndPeppers.VARS_HPWDCTX_HPWDCTX_HPWDCTX,      Defaults.RAND_LEN_BYTES);
		public static final RandomSalt VARS_HKEY_HKEY_HKEY               = new RandomSalt(ParametersAndPeppers.VARS_HKEY_HKEY_HKEY,               Defaults.RAND_LEN_BYTES);
		public static final RandomSalt VARS_HKEYCTX_HKEYCTX_HKEYCTX      = new RandomSalt(ParametersAndPeppers.VARS_HKEYCTX_HKEYCTX_HKEYCTX,      Defaults.RAND_LEN_BYTES);
		public static final RandomSalt VARS_CPWD_CPWD_CPWD               = new RandomSalt(ParametersAndPeppers.VARS_CPWD_CPWD_CPWD,               Defaults.RAND_LEN_BYTES);
		public static final RandomSalt VARS_CPWDCTX_CPWDCTX_CPWDCTX      = new RandomSalt(ParametersAndPeppers.VARS_CPWDCTX_CPWDCTX_CPWDCTX,      Defaults.RAND_LEN_BYTES);
		public static final RandomSalt VARS_CKEY_CKEY_CKEY               = new RandomSalt(ParametersAndPeppers.VARS_CKEY_CKEY_CKEY,               Defaults.RAND_LEN_BYTES);
		public static final RandomSalt VARS_CKEYCTX_CKEYCTX_CKEYCTX      = new RandomSalt(ParametersAndPeppers.VARS_CKEYCTX_CKEYCTX_CKEYCTX,      Defaults.RAND_LEN_BYTES);
	}

	public static final class Derived {
//		public static final DerivedSalt VARS_CONS_NULL_NULL_NULL          = new DerivedSalt(ParametersAndPeppers.VARS_CONS_NULL_NULL_NULL, Defaults.DER_LEN_BYTES);
		public static final DerivedSalt VARS_CONS_NONE_NONE_NONE          = new DerivedSalt(ParametersAndPeppers.VARS_CONS_NONE_NONE_NONE,                Defaults.DER_LEN_BYTES);
		public static final DerivedSalt VARS_CONS_CTX_CTX_CTX             = new DerivedSalt(ParametersAndPeppers.VARS_CONS_CTX_CTX_CTX,                   Defaults.DER_LEN_BYTES);
		public static final DerivedSalt VARS_CONS_HPWD_HPWD_HPWD          = new DerivedSalt(ParametersAndPeppers.VARS_CONS_HPWD_HPWD_HPWD,          Defaults.DER_LEN_BYTES);
		public static final DerivedSalt VARS_CONS_HPWDCTX_HPWDCTX_HPWDCTX = new DerivedSalt(ParametersAndPeppers.VARS_CONS_HPWDCTX_HPWDCTX_HPWDCTX, Defaults.DER_LEN_BYTES);
		public static final DerivedSalt VARS_CONS_HKEY_HKEY_HKEY          = new DerivedSalt(ParametersAndPeppers.VARS_CONS_HKEY_HKEY_HKEY,          Defaults.DER_LEN_BYTES);
		public static final DerivedSalt VARS_CONS_HKEYCTX_HKEYCTX_HKEYCTX = new DerivedSalt(ParametersAndPeppers.VARS_CONS_HKEYCTX_HKEYCTX_HKEYCTX, Defaults.DER_LEN_BYTES);
		public static final DerivedSalt VARS_CONS_CPWD_CPWD_CPWD          = new DerivedSalt(ParametersAndPeppers.VARS_CONS_CPWD_CPWD_CPWD,          Defaults.DER_LEN_BYTES);
		public static final DerivedSalt VARS_CONS_CPWDCTX_CPWDCTX_CPWDCTX = new DerivedSalt(ParametersAndPeppers.VARS_CONS_CPWDCTX_CPWDCTX_CPWDCTX, Defaults.DER_LEN_BYTES);
		public static final DerivedSalt VARS_CONS_CKEY_CKEY_CKEY          = new DerivedSalt(ParametersAndPeppers.VARS_CONS_CKEY_CKEY_CKEY,          Defaults.DER_LEN_BYTES);
		public static final DerivedSalt VARS_CONS_CKEYCTX_CKEYCTX_CKEYCTX = new DerivedSalt(ParametersAndPeppers.VARS_CONS_CKEYCTX_CKEYCTX_CKEYCTX, Defaults.DER_LEN_BYTES);

//		public static final DerivedSalt VARS_NULL_NULL_NULL               = new DerivedSalt(ParametersAndPeppers.VARS_NULL_NULL_NULL, Defaults.DER_LEN_BYTES);
		public static final DerivedSalt VARS_NONE_NONE_NONE               = new DerivedSalt(ParametersAndPeppers.VARS_NONE_NONE_NONE,                Defaults.DER_LEN_BYTES);
		public static final DerivedSalt VARS_CTX_CTX_CTX                  = new DerivedSalt(ParametersAndPeppers.VARS_CTX_CTX_CTX,                   Defaults.DER_LEN_BYTES);
		public static final DerivedSalt VARS_HPWD_HPWD_HPWD               = new DerivedSalt(ParametersAndPeppers.VARS_HPWD_HPWD_HPWD,          Defaults.DER_LEN_BYTES);
		public static final DerivedSalt VARS_HPWDCTX_HPWDCTX_HPWDCTX      = new DerivedSalt(ParametersAndPeppers.VARS_HPWDCTX_HPWDCTX_HPWDCTX, Defaults.DER_LEN_BYTES);
		public static final DerivedSalt VARS_HKEY_HKEY_HKEY               = new DerivedSalt(ParametersAndPeppers.VARS_HKEY_HKEY_HKEY,          Defaults.DER_LEN_BYTES);
		public static final DerivedSalt VARS_HKEYCTX_HKEYCTX_HKEYCTX      = new DerivedSalt(ParametersAndPeppers.VARS_HKEYCTX_HKEYCTX_HKEYCTX, Defaults.DER_LEN_BYTES);
		public static final DerivedSalt VARS_CPWD_CPWD_CPWD               = new DerivedSalt(ParametersAndPeppers.VARS_CPWD_CPWD_CPWD,          Defaults.DER_LEN_BYTES);
		public static final DerivedSalt VARS_CPWDCTX_CPWDCTX_CPWDCTX      = new DerivedSalt(ParametersAndPeppers.VARS_CPWDCTX_CPWDCTX_CPWDCTX, Defaults.DER_LEN_BYTES);
		public static final DerivedSalt VARS_CKEY_CKEY_CKEY               = new DerivedSalt(ParametersAndPeppers.VARS_CKEY_CKEY_CKEY,          Defaults.DER_LEN_BYTES);
		public static final DerivedSalt VARS_CKEYCTX_CKEYCTX_CKEYCTX      = new DerivedSalt(ParametersAndPeppers.VARS_CKEYCTX_CKEYCTX_CKEYCTX, Defaults.DER_LEN_BYTES);

//		public static final DerivedSalt CONS_NULL_NULL_NULL               = new DerivedSalt(ParametersAndPeppers.CONS_NULL_NULL_NULL, Defaults.DER_LEN_BYTES);
		public static final DerivedSalt CONS_NONE_NONE_NONE               = new DerivedSalt(ParametersAndPeppers.CONS_NONE_NONE_NONE,                Defaults.DER_LEN_BYTES);
		public static final DerivedSalt CONS_CTX_CTX_CTX                  = new DerivedSalt(ParametersAndPeppers.CONS_CTX_CTX_CTX,                   Defaults.DER_LEN_BYTES);
		public static final DerivedSalt CONS_HPWD_HPWD_HPWD               = new DerivedSalt(ParametersAndPeppers.CONS_HPWD_HPWD_HPWD,          Defaults.DER_LEN_BYTES);
		public static final DerivedSalt CONS_HPWDCTX_HPWDCTX_HPWDCTX      = new DerivedSalt(ParametersAndPeppers.CONS_HPWDCTX_HPWDCTX_HPWDCTX, Defaults.DER_LEN_BYTES);
		public static final DerivedSalt CONS_HKEY_HKEY_HKEY               = new DerivedSalt(ParametersAndPeppers.CONS_HKEY_HKEY_HKEY,          Defaults.DER_LEN_BYTES);
		public static final DerivedSalt CONS_HKEYCTX_HKEYCTX_HKEYCTX      = new DerivedSalt(ParametersAndPeppers.CONS_HKEYCTX_HKEYCTX_HKEYCTX, Defaults.DER_LEN_BYTES);
		public static final DerivedSalt CONS_CPWD_CPWD_CPWD               = new DerivedSalt(ParametersAndPeppers.CONS_CPWD_CPWD_CPWD,          Defaults.DER_LEN_BYTES);
		public static final DerivedSalt CONS_CPWDCTX_CPWDCTX_CPWDCTX      = new DerivedSalt(ParametersAndPeppers.CONS_CPWDCTX_CPWDCTX_CPWDCTX, Defaults.DER_LEN_BYTES);
		public static final DerivedSalt CONS_CKEY_CKEY_CKEY               = new DerivedSalt(ParametersAndPeppers.CONS_CKEY_CKEY_CKEY,          Defaults.DER_LEN_BYTES);
		public static final DerivedSalt CONS_CKEYCTX_CKEYCTX_CKEYCTX      = new DerivedSalt(ParametersAndPeppers.CONS_CKEYCTX_CKEYCTX_CKEYCTX, Defaults.DER_LEN_BYTES);

//		public static final DerivedSalt NONE_NULL_NULL_NULL               = new DerivedSalt(ParametersAndPeppers.NONE_NULL_NULL_NULL, Defaults.DER_LEN_BYTES);
		public static final DerivedSalt NONE_NONE_NONE_NONE               = new DerivedSalt(ParametersAndPeppers.NONE_NONE_NONE_NONE,                Defaults.DER_LEN_BYTES);
		public static final DerivedSalt NONE_CTX_CTX_CTX                  = new DerivedSalt(ParametersAndPeppers.NONE_CTX_CTX_CTX,                   Defaults.DER_LEN_BYTES);
		public static final DerivedSalt NONE_HPWD_HPWD_HPWD               = new DerivedSalt(ParametersAndPeppers.NONE_HPWD_HPWD_HPWD,          Defaults.DER_LEN_BYTES);
		public static final DerivedSalt NONE_HPWDCTX_HPWDCTX_HPWDCTX      = new DerivedSalt(ParametersAndPeppers.NONE_HPWDCTX_HPWDCTX_HPWDCTX, Defaults.DER_LEN_BYTES);
		public static final DerivedSalt NONE_HKEY_HKEY_HKEY               = new DerivedSalt(ParametersAndPeppers.NONE_HKEY_HKEY_HKEY,          Defaults.DER_LEN_BYTES);
		public static final DerivedSalt NONE_HKEYCTX_HKEYCTX_HKEYCTX      = new DerivedSalt(ParametersAndPeppers.NONE_HKEYCTX_HKEYCTX_HKEYCTX, Defaults.DER_LEN_BYTES);
		public static final DerivedSalt NONE_CPWD_CPWD_CPWD               = new DerivedSalt(ParametersAndPeppers.NONE_CPWD_CPWD_CPWD,          Defaults.DER_LEN_BYTES);
		public static final DerivedSalt NONE_CPWDCTX_CPWDCTX_CPWDCTX      = new DerivedSalt(ParametersAndPeppers.NONE_CPWDCTX_CPWDCTX_CPWDCTX, Defaults.DER_LEN_BYTES);
		public static final DerivedSalt NONE_CKEY_CKEY_CKEY               = new DerivedSalt(ParametersAndPeppers.NONE_CKEY_CKEY_CKEY,          Defaults.DER_LEN_BYTES);
		public static final DerivedSalt NONE_CKEYCTX_CKEYCTX_CKEYCTX      = new DerivedSalt(ParametersAndPeppers.NONE_CKEYCTX_CKEYCTX_CKEYCTX, Defaults.DER_LEN_BYTES);
	}

	public static final class Constant {
		public static final ConstantSalt VARS_CONS_NULL_NULL_NULL          = new ConstantSalt(ParametersAndPeppers.VARS_CONS_NULL_NULL_NULL,                Defaults.CONST_BYTES);
		public static final ConstantSalt VARS_CONS_NONE_NONE_NONE          = new ConstantSalt(ParametersAndPeppers.VARS_CONS_NONE_NONE_NONE,                Defaults.CONST_BYTES);
		public static final ConstantSalt VARS_CONS_CTX_CTX_CTX             = new ConstantSalt(ParametersAndPeppers.VARS_CONS_CTX_CTX_CTX,                   Defaults.CONST_BYTES);
		public static final ConstantSalt VARS_CONS_HPWD_HPWD_HPWD          = new ConstantSalt(ParametersAndPeppers.VARS_CONS_HPWD_HPWD_HPWD,          Defaults.CONST_BYTES);
		public static final ConstantSalt VARS_CONS_HPWDCTX_HPWDCTX_HPWDCTX = new ConstantSalt(ParametersAndPeppers.VARS_CONS_HPWDCTX_HPWDCTX_HPWDCTX, Defaults.CONST_BYTES);
		public static final ConstantSalt VARS_CONS_HKEY_HKEY_HKEY          = new ConstantSalt(ParametersAndPeppers.VARS_CONS_HKEY_HKEY_HKEY,          Defaults.CONST_BYTES);
		public static final ConstantSalt VARS_CONS_HKEYCTX_HKEYCTX_HKEYCTX = new ConstantSalt(ParametersAndPeppers.VARS_CONS_HKEYCTX_HKEYCTX_HKEYCTX, Defaults.CONST_BYTES);
		public static final ConstantSalt VARS_CONS_CPWD_CPWD_CPWD          = new ConstantSalt(ParametersAndPeppers.VARS_CONS_CPWD_CPWD_CPWD,          Defaults.CONST_BYTES);
		public static final ConstantSalt VARS_CONS_CPWDCTX_CPWDCTX_CPWDCTX = new ConstantSalt(ParametersAndPeppers.VARS_CONS_CPWDCTX_CPWDCTX_CPWDCTX, Defaults.CONST_BYTES);
		public static final ConstantSalt VARS_CONS_CKEY_CKEY_CKEY          = new ConstantSalt(ParametersAndPeppers.VARS_CONS_CKEY_CKEY_CKEY,          Defaults.CONST_BYTES);
		public static final ConstantSalt VARS_CONS_CKEYCTX_CKEYCTX_CKEYCTX = new ConstantSalt(ParametersAndPeppers.VARS_CONS_CKEYCTX_CKEYCTX_CKEYCTX, Defaults.CONST_BYTES);

		public static final ConstantSalt VARS_NULL_NULL_NULL               = new ConstantSalt(ParametersAndPeppers.VARS_NULL_NULL_NULL,                Defaults.CONST_BYTES);
		public static final ConstantSalt VARS_NONE_NONE_NONE               = new ConstantSalt(ParametersAndPeppers.VARS_NONE_NONE_NONE,                Defaults.CONST_BYTES);
		public static final ConstantSalt VARS_CTX_CTX_CTX                  = new ConstantSalt(ParametersAndPeppers.VARS_CTX_CTX_CTX,                   Defaults.CONST_BYTES);
		public static final ConstantSalt VARS_HPWD_HPWD_HPWD               = new ConstantSalt(ParametersAndPeppers.VARS_HPWD_HPWD_HPWD,          Defaults.CONST_BYTES);
		public static final ConstantSalt VARS_HPWDCTX_HPWDCTX_HPWDCTX      = new ConstantSalt(ParametersAndPeppers.VARS_HPWDCTX_HPWDCTX_HPWDCTX, Defaults.CONST_BYTES);
		public static final ConstantSalt VARS_HKEY_HKEY_HKEY               = new ConstantSalt(ParametersAndPeppers.VARS_HKEY_HKEY_HKEY,          Defaults.CONST_BYTES);
		public static final ConstantSalt VARS_HKEYCTX_HKEYCTX_HKEYCTX      = new ConstantSalt(ParametersAndPeppers.VARS_HKEYCTX_HKEYCTX_HKEYCTX, Defaults.CONST_BYTES);
		public static final ConstantSalt VARS_CPWD_CPWD_CPWD               = new ConstantSalt(ParametersAndPeppers.VARS_CPWD_CPWD_CPWD,          Defaults.CONST_BYTES);
		public static final ConstantSalt VARS_CPWDCTX_CPWDCTX_CPWDCTX      = new ConstantSalt(ParametersAndPeppers.VARS_CPWDCTX_CPWDCTX_CPWDCTX, Defaults.CONST_BYTES);
		public static final ConstantSalt VARS_CKEY_CKEY_CKEY               = new ConstantSalt(ParametersAndPeppers.VARS_CKEY_CKEY_CKEY,          Defaults.CONST_BYTES);
		public static final ConstantSalt VARS_CKEYCTX_CKEYCTX_CKEYCTX      = new ConstantSalt(ParametersAndPeppers.VARS_CKEYCTX_CKEYCTX_CKEYCTX, Defaults.CONST_BYTES);

		public static final ConstantSalt CONS_NULL_NULL_NULL               = new ConstantSalt(ParametersAndPeppers.CONS_NULL_NULL_NULL,                Defaults.CONST_BYTES);
		public static final ConstantSalt CONS_NONE_NONE_NONE               = new ConstantSalt(ParametersAndPeppers.CONS_NONE_NONE_NONE,                Defaults.CONST_BYTES);
		public static final ConstantSalt CONS_CTX_CTX_CTX                  = new ConstantSalt(ParametersAndPeppers.CONS_CTX_CTX_CTX,                   Defaults.CONST_BYTES);
		public static final ConstantSalt CONS_HPWD_HPWD_HPWD               = new ConstantSalt(ParametersAndPeppers.CONS_HPWD_HPWD_HPWD,          Defaults.CONST_BYTES);
		public static final ConstantSalt CONS_HPWDCTX_HPWDCTX_HPWDCTX      = new ConstantSalt(ParametersAndPeppers.CONS_HPWDCTX_HPWDCTX_HPWDCTX, Defaults.CONST_BYTES);
		public static final ConstantSalt CONS_HKEY_HKEY_HKEY               = new ConstantSalt(ParametersAndPeppers.CONS_HKEY_HKEY_HKEY,          Defaults.CONST_BYTES);
		public static final ConstantSalt CONS_HKEYCTX_HKEYCTX_HKEYCTX      = new ConstantSalt(ParametersAndPeppers.CONS_HKEYCTX_HKEYCTX_HKEYCTX, Defaults.CONST_BYTES);
		public static final ConstantSalt CONS_CPWD_CPWD_CPWD               = new ConstantSalt(ParametersAndPeppers.CONS_CPWD_CPWD_CPWD,          Defaults.CONST_BYTES);
		public static final ConstantSalt CONS_CPWDCTX_CPWDCTX_CPWDCTX      = new ConstantSalt(ParametersAndPeppers.CONS_CPWDCTX_CPWDCTX_CPWDCTX, Defaults.CONST_BYTES);
		public static final ConstantSalt CONS_CKEY_CKEY_CKEY               = new ConstantSalt(ParametersAndPeppers.CONS_CKEY_CKEY_CKEY,          Defaults.CONST_BYTES);
		public static final ConstantSalt CONS_CKEYCTX_CKEYCTX_CKEYCTX      = new ConstantSalt(ParametersAndPeppers.CONS_CKEYCTX_CKEYCTX_CKEYCTX, Defaults.CONST_BYTES);

		public static final ConstantSalt NONE_NULL_NULL_NULL               = new ConstantSalt(ParametersAndPeppers.NONE_NULL_NULL_NULL,                Defaults.CONST_BYTES);
		public static final ConstantSalt NONE_NONE_NONE_NONE               = new ConstantSalt(ParametersAndPeppers.NONE_NONE_NONE_NONE,                Defaults.CONST_BYTES);
		public static final ConstantSalt NONE_CTX_CTX_CTX                  = new ConstantSalt(ParametersAndPeppers.NONE_CTX_CTX_CTX,                   Defaults.CONST_BYTES);
		public static final ConstantSalt NONE_HPWD_HPWD_HPWD               = new ConstantSalt(ParametersAndPeppers.NONE_HPWD_HPWD_HPWD,          Defaults.CONST_BYTES);
		public static final ConstantSalt NONE_HPWDCTX_HPWDCTX_HPWDCTX      = new ConstantSalt(ParametersAndPeppers.NONE_HPWDCTX_HPWDCTX_HPWDCTX, Defaults.CONST_BYTES);
		public static final ConstantSalt NONE_HKEY_HKEY_HKEY               = new ConstantSalt(ParametersAndPeppers.NONE_HKEY_HKEY_HKEY,          Defaults.CONST_BYTES);
		public static final ConstantSalt NONE_HKEYCTX_HKEYCTX_HKEYCTX      = new ConstantSalt(ParametersAndPeppers.NONE_HKEYCTX_HKEYCTX_HKEYCTX, Defaults.CONST_BYTES);
		public static final ConstantSalt NONE_CPWD_CPWD_CPWD               = new ConstantSalt(ParametersAndPeppers.NONE_CPWD_CPWD_CPWD,          Defaults.CONST_BYTES);
		public static final ConstantSalt NONE_CPWDCTX_CPWDCTX_CPWDCTX      = new ConstantSalt(ParametersAndPeppers.NONE_CPWDCTX_CPWDCTX_CPWDCTX, Defaults.CONST_BYTES);
		public static final ConstantSalt NONE_CKEY_CKEY_CKEY               = new ConstantSalt(ParametersAndPeppers.NONE_CKEY_CKEY_CKEY,          Defaults.CONST_BYTES);
		public static final ConstantSalt NONE_CKEYCTX_CKEYCTX_CKEYCTX      = new ConstantSalt(ParametersAndPeppers.NONE_CKEYCTX_CKEYCTX_CKEYCTX, Defaults.CONST_BYTES);
	}

	public static class Defaults {
		public static final int ITER = 1; // OWASP recommends 600_000 in production
		public static final int DK_BYTES_LEN = 32;
		public static final Pbkdf2AlgorithmV1 PRF_ALG = Pbkdf2AlgorithmV1.PBKDF2WithHmacSHA256;

		public static final int RAND_LEN_BYTES = 32;
		public static final int DER_LEN_BYTES = 32;
		public static final byte[] CONST_BYTES = "constant-salt-bytes".getBytes(StandardCharsets.UTF_8);

		public static final HashCodec B64_STD_CB_NONE      = new HashCodec(TextCodec.B64_STD, "|", ":", Flags.NONE);
		public static final HashCodec B64_STD_CB_VARS      = new HashCodec(TextCodec.B64_STD, "|", ":", Flags.VARS);
		public static final HashCodec B64_STD_CB_CONS      = new HashCodec(TextCodec.B64_STD, "|", ":", Flags.CONS);
		public static final HashCodec B64_STD_CB_VARS_CONS = new HashCodec(TextCodec.B64_STD, "|", ":", Flags.BOTH);
	}

	public static class Codec {
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

	public static class InputVariables {
		public static final SecretKey CK = new SecretKeySpec(new byte[32], PepperOptions.CMAC_ALG.algorithm());
		public static final SecretKey CP = null;
		public static final SecretKey HK = new SecretKeySpec("pre-salt-key".getBytes(StandardCharsets.UTF_8), PepperOptions.HMAC_ALG.algorithm());
		public static final SecretKey HP = null;

		public static final HashPepperInputVariables NULL    = null;
		public static final HashPepperInputVariables NONE    = new HashPepperInputVariables(new Pepper(null, null,                  new byte[0], new byte[0], PepperOptions.HMAC_ALG, PepperOptions.ENC_DEC));
		public static final HashPepperInputVariables CTX     = new HashPepperInputVariables(new Pepper(null, null,                  new byte[7], new byte[3], PepperOptions.HMAC_ALG, PepperOptions.ENC_DEC));
		public static final HashPepperInputVariables HPWD    = new HashPepperInputVariables(new Pepper(HP,   null,                  new byte[0], new byte[0], PepperOptions.HMAC_ALG, PepperOptions.ENC_DEC));
		public static final HashPepperInputVariables HPWDCTX = new HashPepperInputVariables(new Pepper(HP,   null,                  new byte[3], new byte[2], PepperOptions.HMAC_ALG, PepperOptions.ENC_DEC));
		public static final HashPepperInputVariables HKEY    = new HashPepperInputVariables(new Pepper(HK,   null,                  new byte[0], new byte[0], PepperOptions.HMAC_ALG, PepperOptions.ENC_DEC));
		public static final HashPepperInputVariables HKEYCTX = new HashPepperInputVariables(new Pepper(HK,   null,                  new byte[3], new byte[2], PepperOptions.HMAC_ALG, PepperOptions.ENC_DEC));
		public static final HashPepperInputVariables CPWD    = new HashPepperInputVariables(new Pepper(CP,   PepperOptions.DER_ALG, new byte[0], new byte[0], PepperOptions.CMAC_ALG, PepperOptions.ENC_DEC));
		public static final HashPepperInputVariables CPWDCTX = new HashPepperInputVariables(new Pepper(CP,   PepperOptions.DER_ALG, new byte[3], new byte[2], PepperOptions.CMAC_ALG, PepperOptions.ENC_DEC));
		public static final HashPepperInputVariables CKEY    = new HashPepperInputVariables(new Pepper(CK,   PepperOptions.DER_ALG, new byte[0], new byte[0], PepperOptions.CMAC_ALG, PepperOptions.ENC_DEC));
		public static final HashPepperInputVariables CKEYCTX = new HashPepperInputVariables(new Pepper(CK,   PepperOptions.DER_ALG, new byte[3], new byte[2], PepperOptions.CMAC_ALG, PepperOptions.ENC_DEC));
	}

	public static class PreHash {
		public static final SecretKey CK = new SecretKeySpec(new byte[32], PepperOptions.CMAC_ALG.algorithm());
		public static final SecretKey CP = null;
		public static final SecretKey HK = new SecretKeySpec("pre-hash-key".getBytes(StandardCharsets.UTF_8), PepperOptions.HMAC_ALG.algorithm());
		public static final SecretKey HP = null;

		public static final HashPepperPreHash NULL    = null;
		public static final HashPepperPreHash NONE    = new HashPepperPreHash(new Pepper(null,  null,                  new byte[0], new byte[0], PepperOptions.HMAC_ALG, PepperOptions.ENC_DEC));
		public static final HashPepperPreHash CTX     = new HashPepperPreHash(new Pepper(null,  null,                  new byte[7], new byte[3], PepperOptions.HMAC_ALG, PepperOptions.ENC_DEC));
		public static final HashPepperPreHash HPWD    = new HashPepperPreHash(new Pepper(HP,    null,                  new byte[0], new byte[0], PepperOptions.HMAC_ALG, PepperOptions.ENC_DEC));
		public static final HashPepperPreHash HPWDCTX = new HashPepperPreHash(new Pepper(HP,    null,                  new byte[3], new byte[2], PepperOptions.HMAC_ALG, PepperOptions.ENC_DEC));
		public static final HashPepperPreHash HKEY    = new HashPepperPreHash(new Pepper(HK,    null,                  new byte[0], new byte[0], PepperOptions.HMAC_ALG, PepperOptions.ENC_DEC));
		public static final HashPepperPreHash HKEYCTX = new HashPepperPreHash(new Pepper(HK,    null,                  new byte[3], new byte[2], PepperOptions.HMAC_ALG, PepperOptions.ENC_DEC));
		public static final HashPepperPreHash CPWD    = new HashPepperPreHash(new Pepper(CP,    PepperOptions.DER_ALG, new byte[0], new byte[0], PepperOptions.CMAC_ALG, PepperOptions.ENC_DEC));
		public static final HashPepperPreHash CPWDCTX = new HashPepperPreHash(new Pepper(CP,    PepperOptions.DER_ALG, new byte[3], new byte[2], PepperOptions.CMAC_ALG, PepperOptions.ENC_DEC));
		public static final HashPepperPreHash CKEY    = new HashPepperPreHash(new Pepper(CK,    PepperOptions.DER_ALG, new byte[0], new byte[0], PepperOptions.CMAC_ALG, PepperOptions.ENC_DEC));
		public static final HashPepperPreHash CKEYCTX = new HashPepperPreHash(new Pepper(CK,    PepperOptions.DER_ALG, new byte[3], new byte[2], PepperOptions.CMAC_ALG, PepperOptions.ENC_DEC));
	}

	public static class PostHash {
		public static final SecretKey CK = new SecretKeySpec(new byte[32], PepperOptions.CMAC_ALG.algorithm());
		public static final SecretKey CP = null;
		public static final SecretKey HK = new SecretKeySpec("post-hash-key".getBytes(StandardCharsets.UTF_8), PepperOptions.HMAC_ALG.algorithm());
		public static final SecretKey HP = null;

		public static final HashPepperPostHash NULL    = null;
		public static final HashPepperPostHash NONE    = new HashPepperPostHash(new Pepper(null,  null,                  new byte[0], new byte[0], PepperOptions.HMAC_ALG, PepperOptions.ENC_DEC));
		public static final HashPepperPostHash CTX     = new HashPepperPostHash(new Pepper(null,  null,                  new byte[7], new byte[3], PepperOptions.HMAC_ALG, PepperOptions.ENC_DEC));
		public static final HashPepperPostHash HPWD    = new HashPepperPostHash(new Pepper(HP,    null,                  new byte[0], new byte[0], PepperOptions.HMAC_ALG, PepperOptions.ENC_DEC));
		public static final HashPepperPostHash HPWDCTX = new HashPepperPostHash(new Pepper(HP,    null,                  new byte[3], new byte[2], PepperOptions.HMAC_ALG, PepperOptions.ENC_DEC));
		public static final HashPepperPostHash HKEY    = new HashPepperPostHash(new Pepper(HK,    null,                  new byte[0], new byte[0], PepperOptions.HMAC_ALG, PepperOptions.ENC_DEC));
		public static final HashPepperPostHash HKEYCTX = new HashPepperPostHash(new Pepper(HK,    null,                  new byte[3], new byte[2], PepperOptions.HMAC_ALG, PepperOptions.ENC_DEC));
		public static final HashPepperPostHash CPWD    = new HashPepperPostHash(new Pepper(CP,    PepperOptions.DER_ALG, new byte[0], new byte[0], PepperOptions.CMAC_ALG, PepperOptions.ENC_DEC));
		public static final HashPepperPostHash CPWDCTX = new HashPepperPostHash(new Pepper(CP,    PepperOptions.DER_ALG, new byte[3], new byte[2], PepperOptions.CMAC_ALG, PepperOptions.ENC_DEC));
		public static final HashPepperPostHash CKEY    = new HashPepperPostHash(new Pepper(CK,    PepperOptions.DER_ALG, new byte[0], new byte[0], PepperOptions.CMAC_ALG, PepperOptions.ENC_DEC));
		public static final HashPepperPostHash CKEYCTX = new HashPepperPostHash(new Pepper(CK,    PepperOptions.DER_ALG, new byte[3], new byte[2], PepperOptions.CMAC_ALG, PepperOptions.ENC_DEC));
	}

	// 125 Tuples of Peppers => PeppperPreSalt{NULL,NONE,CTX,SK,SKCTX} x PeppperPreHash{NULL,NONE,CTX,SK,SKCTX} x PeppperPostHash{NULL,NONE,CTX,SK,SKCTX})
	public static class Peppers {
		public static final HashPeppers NULL_NULL_NULL          = new HashPeppers(InputVariables.NULL,      PreHash.NULL,      PostHash.NULL);
		public static final HashPeppers NONE_NONE_NONE          = new HashPeppers(InputVariables.NONE,      PreHash.NONE,      PostHash.NONE);
		public static final HashPeppers CTX_CTX_CTX             = new HashPeppers(InputVariables.CTX,       PreHash.CTX,       PostHash.CTX);
		public static final HashPeppers HPWD_HPWD_HPWD          = new HashPeppers(InputVariables.HPWD,    PreHash.HPWD,    PostHash.HPWD);
		public static final HashPeppers HPWDCTX_HPWDCTX_HPWDCTX = new HashPeppers(InputVariables.HPWDCTX, PreHash.HPWDCTX, PostHash.HPWDCTX);
		public static final HashPeppers HKEY_HKEY_HKEY          = new HashPeppers(InputVariables.HKEY,    PreHash.HKEY,    PostHash.HKEY);
		public static final HashPeppers HKEYCTX_HKEYCTX_HKEYCTX = new HashPeppers(InputVariables.HKEYCTX, PreHash.HKEYCTX, PostHash.HKEYCTX);
		public static final HashPeppers CPWD_CPWD_CPWD          = new HashPeppers(InputVariables.CPWD,    PreHash.CPWD,    PostHash.CPWD);
		public static final HashPeppers CPWDCTX_CPWDCTX_CPWDCTX = new HashPeppers(InputVariables.CPWDCTX, PreHash.CPWDCTX, PostHash.CPWDCTX);
		public static final HashPeppers CKEY_CKEY_CKEY          = new HashPeppers(InputVariables.CKEY,    PreHash.CKEY,    PostHash.CKEY);
		public static final HashPeppers CKEYCTX_CKEYCTX_CKEYCTX = new HashPeppers(InputVariables.CKEYCTX, PreHash.CKEYCTX, PostHash.CKEYCTX);
	}

	// Key+Context pairs for Macs
	public static class ParametersAndPeppers {
		public static final HashInputConstantsAndHashPeppers NONE_NULL_NULL_NULL          = new HashInputConstantsAndHashPeppers(Codec.B64_STD_CB_NONE, Peppers.NULL_NULL_NULL);
		public static final HashInputConstantsAndHashPeppers NONE_NONE_NONE_NONE          = new HashInputConstantsAndHashPeppers(Codec.B64_STD_CB_NONE, Peppers.NONE_NONE_NONE);
		public static final HashInputConstantsAndHashPeppers NONE_CTX_CTX_CTX             = new HashInputConstantsAndHashPeppers(Codec.B64_STD_CB_NONE, Peppers.CTX_CTX_CTX);
		public static final HashInputConstantsAndHashPeppers NONE_HPWD_HPWD_HPWD          = new HashInputConstantsAndHashPeppers(Codec.B64_STD_CB_NONE, Peppers.HPWD_HPWD_HPWD);
		public static final HashInputConstantsAndHashPeppers NONE_HPWDCTX_HPWDCTX_HPWDCTX = new HashInputConstantsAndHashPeppers(Codec.B64_STD_CB_NONE, Peppers.HPWDCTX_HPWDCTX_HPWDCTX);
		public static final HashInputConstantsAndHashPeppers NONE_HKEY_HKEY_HKEY          = new HashInputConstantsAndHashPeppers(Codec.B64_STD_CB_NONE, Peppers.HKEY_HKEY_HKEY);
		public static final HashInputConstantsAndHashPeppers NONE_HKEYCTX_HKEYCTX_HKEYCTX = new HashInputConstantsAndHashPeppers(Codec.B64_STD_CB_NONE, Peppers.HKEYCTX_HKEYCTX_HKEYCTX);
		public static final HashInputConstantsAndHashPeppers NONE_CPWD_CPWD_CPWD          = new HashInputConstantsAndHashPeppers(Codec.B64_STD_CB_NONE, Peppers.CPWD_CPWD_CPWD);
		public static final HashInputConstantsAndHashPeppers NONE_CPWDCTX_CPWDCTX_CPWDCTX = new HashInputConstantsAndHashPeppers(Codec.B64_STD_CB_NONE, Peppers.CPWDCTX_CPWDCTX_CPWDCTX);
		public static final HashInputConstantsAndHashPeppers NONE_CKEY_CKEY_CKEY          = new HashInputConstantsAndHashPeppers(Codec.B64_STD_CB_NONE, Peppers.CKEY_CKEY_CKEY);
		public static final HashInputConstantsAndHashPeppers NONE_CKEYCTX_CKEYCTX_CKEYCTX = new HashInputConstantsAndHashPeppers(Codec.B64_STD_CB_NONE, Peppers.CKEYCTX_CKEYCTX_CKEYCTX);

		public static final HashInputConstantsAndHashPeppers VARS_NULL_NULL_NULL          = new HashInputConstantsAndHashPeppers(Codec.B64_STD_CB_VARS, Peppers.NULL_NULL_NULL);
		public static final HashInputConstantsAndHashPeppers VARS_NONE_NONE_NONE          = new HashInputConstantsAndHashPeppers(Codec.B64_STD_CB_VARS, Peppers.NONE_NONE_NONE);
		public static final HashInputConstantsAndHashPeppers VARS_CTX_CTX_CTX             = new HashInputConstantsAndHashPeppers(Codec.B64_STD_CB_VARS, Peppers.CTX_CTX_CTX);
		public static final HashInputConstantsAndHashPeppers VARS_HPWD_HPWD_HPWD          = new HashInputConstantsAndHashPeppers(Codec.B64_STD_CB_VARS, Peppers.HPWD_HPWD_HPWD);
		public static final HashInputConstantsAndHashPeppers VARS_HPWDCTX_HPWDCTX_HPWDCTX = new HashInputConstantsAndHashPeppers(Codec.B64_STD_CB_VARS, Peppers.HPWDCTX_HPWDCTX_HPWDCTX);
		public static final HashInputConstantsAndHashPeppers VARS_HKEY_HKEY_HKEY          = new HashInputConstantsAndHashPeppers(Codec.B64_STD_CB_VARS, Peppers.HKEY_HKEY_HKEY);
		public static final HashInputConstantsAndHashPeppers VARS_HKEYCTX_HKEYCTX_HKEYCTX = new HashInputConstantsAndHashPeppers(Codec.B64_STD_CB_VARS, Peppers.HKEYCTX_HKEYCTX_HKEYCTX);
		public static final HashInputConstantsAndHashPeppers VARS_CPWD_CPWD_CPWD          = new HashInputConstantsAndHashPeppers(Codec.B64_STD_CB_VARS, Peppers.CPWD_CPWD_CPWD);
		public static final HashInputConstantsAndHashPeppers VARS_CPWDCTX_CPWDCTX_CPWDCTX = new HashInputConstantsAndHashPeppers(Codec.B64_STD_CB_VARS, Peppers.CPWDCTX_CPWDCTX_CPWDCTX);
		public static final HashInputConstantsAndHashPeppers VARS_CKEY_CKEY_CKEY          = new HashInputConstantsAndHashPeppers(Codec.B64_STD_CB_VARS, Peppers.CKEY_CKEY_CKEY);
		public static final HashInputConstantsAndHashPeppers VARS_CKEYCTX_CKEYCTX_CKEYCTX = new HashInputConstantsAndHashPeppers(Codec.B64_STD_CB_VARS, Peppers.CKEYCTX_CKEYCTX_CKEYCTX);

		public static final HashInputConstantsAndHashPeppers CONS_NULL_NULL_NULL          = new HashInputConstantsAndHashPeppers(Codec.B64_STD_CB_CONS, Peppers.NULL_NULL_NULL);
		public static final HashInputConstantsAndHashPeppers CONS_NONE_NONE_NONE          = new HashInputConstantsAndHashPeppers(Codec.B64_STD_CB_CONS, Peppers.NONE_NONE_NONE);
		public static final HashInputConstantsAndHashPeppers CONS_CTX_CTX_CTX             = new HashInputConstantsAndHashPeppers(Codec.B64_STD_CB_CONS, Peppers.CTX_CTX_CTX);
		public static final HashInputConstantsAndHashPeppers CONS_HPWD_HPWD_HPWD          = new HashInputConstantsAndHashPeppers(Codec.B64_STD_CB_CONS, Peppers.HPWD_HPWD_HPWD);
		public static final HashInputConstantsAndHashPeppers CONS_HPWDCTX_HPWDCTX_HPWDCTX = new HashInputConstantsAndHashPeppers(Codec.B64_STD_CB_CONS, Peppers.HPWDCTX_HPWDCTX_HPWDCTX);
		public static final HashInputConstantsAndHashPeppers CONS_HKEY_HKEY_HKEY          = new HashInputConstantsAndHashPeppers(Codec.B64_STD_CB_CONS, Peppers.HKEY_HKEY_HKEY);
		public static final HashInputConstantsAndHashPeppers CONS_HKEYCTX_HKEYCTX_HKEYCTX = new HashInputConstantsAndHashPeppers(Codec.B64_STD_CB_CONS, Peppers.HKEYCTX_HKEYCTX_HKEYCTX);
		public static final HashInputConstantsAndHashPeppers CONS_CPWD_CPWD_CPWD          = new HashInputConstantsAndHashPeppers(Codec.B64_STD_CB_CONS, Peppers.CPWD_CPWD_CPWD);
		public static final HashInputConstantsAndHashPeppers CONS_CPWDCTX_CPWDCTX_CPWDCTX = new HashInputConstantsAndHashPeppers(Codec.B64_STD_CB_CONS, Peppers.CPWDCTX_CPWDCTX_CPWDCTX);
		public static final HashInputConstantsAndHashPeppers CONS_CKEY_CKEY_CKEY          = new HashInputConstantsAndHashPeppers(Codec.B64_STD_CB_CONS, Peppers.CKEY_CKEY_CKEY);
		public static final HashInputConstantsAndHashPeppers CONS_CKEYCTX_CKEYCTX_CKEYCTX = new HashInputConstantsAndHashPeppers(Codec.B64_STD_CB_CONS, Peppers.CKEYCTX_CKEYCTX_CKEYCTX);

		public static final HashInputConstantsAndHashPeppers VARS_CONS_NULL_NULL_NULL          = new HashInputConstantsAndHashPeppers(Codec.B64_STD_CB_VARS_CONS, Peppers.NULL_NULL_NULL);
		public static final HashInputConstantsAndHashPeppers VARS_CONS_NONE_NONE_NONE          = new HashInputConstantsAndHashPeppers(Codec.B64_STD_CB_VARS_CONS, Peppers.NONE_NONE_NONE);
		public static final HashInputConstantsAndHashPeppers VARS_CONS_CTX_CTX_CTX             = new HashInputConstantsAndHashPeppers(Codec.B64_STD_CB_VARS_CONS, Peppers.CTX_CTX_CTX);
		public static final HashInputConstantsAndHashPeppers VARS_CONS_HPWD_HPWD_HPWD          = new HashInputConstantsAndHashPeppers(Codec.B64_STD_CB_VARS_CONS, Peppers.HPWD_HPWD_HPWD);
		public static final HashInputConstantsAndHashPeppers VARS_CONS_HPWDCTX_HPWDCTX_HPWDCTX = new HashInputConstantsAndHashPeppers(Codec.B64_STD_CB_VARS_CONS, Peppers.HPWDCTX_HPWDCTX_HPWDCTX);
		public static final HashInputConstantsAndHashPeppers VARS_CONS_HKEY_HKEY_HKEY          = new HashInputConstantsAndHashPeppers(Codec.B64_STD_CB_VARS_CONS, Peppers.HKEY_HKEY_HKEY);
		public static final HashInputConstantsAndHashPeppers VARS_CONS_HKEYCTX_HKEYCTX_HKEYCTX = new HashInputConstantsAndHashPeppers(Codec.B64_STD_CB_VARS_CONS, Peppers.HKEYCTX_HKEYCTX_HKEYCTX);
		public static final HashInputConstantsAndHashPeppers VARS_CONS_CPWD_CPWD_CPWD          = new HashInputConstantsAndHashPeppers(Codec.B64_STD_CB_VARS_CONS, Peppers.CPWD_CPWD_CPWD);
		public static final HashInputConstantsAndHashPeppers VARS_CONS_CPWDCTX_CPWDCTX_CPWDCTX = new HashInputConstantsAndHashPeppers(Codec.B64_STD_CB_VARS_CONS, Peppers.CPWDCTX_CPWDCTX_CPWDCTX);
		public static final HashInputConstantsAndHashPeppers VARS_CONS_CKEY_CKEY_CKEY          = new HashInputConstantsAndHashPeppers(Codec.B64_STD_CB_VARS_CONS, Peppers.CKEY_CKEY_CKEY);
		public static final HashInputConstantsAndHashPeppers VARS_CONS_CKEYCTX_CKEYCTX_CKEYCTX = new HashInputConstantsAndHashPeppers(Codec.B64_STD_CB_VARS_CONS, Peppers.CKEYCTX_CKEYCTX_CKEYCTX);
	}
}
