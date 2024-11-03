package com.github.justincranford.springs.persistenceorm.base.entity;

import java.nio.ByteBuffer;
import java.util.concurrent.atomic.AtomicInteger;

import com.github.justincranford.springs.util.basic.SecureRandomUtil;

import lombok.extern.slf4j.Slf4j;

@Slf4j
@SuppressWarnings({"nls", "unused"})
public class ExternalIdUtil {
	public static final int BYTES_LENGTH = Constants.RANDOM ? 40 : 2;

	public static byte[] generate() {
		if (Constants.RANDOM) {
			return SecureRandomUtil.timeStampBytesAndRandomBytes(8, 32);
		}
		final int id = Constants.ID.getAndIncrement();
		log.info("id: {}", Integer.toString(id));
		if (BYTES_LENGTH == 1) {
			return ByteBuffer.allocate(BYTES_LENGTH).put((byte) id).array();
		} else if (BYTES_LENGTH == 2) {
			return ByteBuffer.allocate(BYTES_LENGTH).putShort((short) id).array();
		} else if (BYTES_LENGTH == 4) {
			return ByteBuffer.allocate(BYTES_LENGTH).putInt(id).array();
		} else if (BYTES_LENGTH == 8) {
			return ByteBuffer.allocate(BYTES_LENGTH).putLong(id).array();
		}
		throw new RuntimeException("Unsupported bytes length " + BYTES_LENGTH);
	}

	private static class Constants {
		private static final boolean RANDOM = false;
		private static final AtomicInteger ID = new AtomicInteger(1);
	}
}

