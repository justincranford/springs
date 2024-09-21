package com.github.justincranford.springs.util.security.hashes.mac;
import javax.crypto.SecretKey;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.Mac;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.macs.CMac;
import org.bouncycastle.crypto.params.KeyParameter;

public class CmacUtil {
	public static byte[] compute(final SecretKey secretKey, final byte[] rawInput) {
        final CipherParameters cipherParameters = new KeyParameter(secretKey.getEncoded());
        final Mac cmac = new CMac(AESEngine.newInstance());
        final byte[] macResult = new byte[cmac.getMacSize()];
        cmac.init(cipherParameters);
        cmac.update(rawInput, 0, rawInput.length);
        cmac.doFinal(macResult, 0);
        return macResult;
	}
}
