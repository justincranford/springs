package com.github.justincranford.springs.persistenceorm.base.entity;

import java.nio.ByteBuffer;
import java.util.concurrent.atomic.AtomicInteger;

import com.github.justincranford.springs.util.basic.SecureRandomUtil;

import lombok.extern.slf4j.Slf4j;

@Slf4j
@SuppressWarnings({"nls"})
public class ExternalIdGenerator {
	public static final int TOTAL_BYTES_LENGTH = Constants.USE_TIMESTAMP_AND_RANDOM_BYTES ? Constants.TIMESTAMP_BYTES + Constants.RANDOM_BYTES : Constants.COUNTER_BYTES;

	public static byte[] generate() {
		if (Constants.USE_TIMESTAMP_AND_RANDOM_BYTES) {
			return SecureRandomUtil.timeStampBytesAndRandomBytes(Constants.TIMESTAMP_BYTES, Constants.RANDOM_BYTES);
		}
		final int id = Constants.COUNTER_ID.getAndIncrement();
		log.info("id: {}", Integer.toString(id));
		return switch(TOTAL_BYTES_LENGTH) {
			case 1 -> ByteBuffer.allocate(TOTAL_BYTES_LENGTH).put((byte) id).array();
			case 2 -> ByteBuffer.allocate(TOTAL_BYTES_LENGTH).putShort((short) id).array();
			case 4 -> ByteBuffer.allocate(TOTAL_BYTES_LENGTH).putInt(id).array();
			case 8 -> ByteBuffer.allocate(TOTAL_BYTES_LENGTH).putLong(id).array();
			default -> throw new RuntimeException("Unsupported bytes length " + TOTAL_BYTES_LENGTH);
		};
	}

	public static class Constants {
		private static final boolean USE_TIMESTAMP_AND_RANDOM_BYTES = false; // true recommended
		private static final int TIMESTAMP_BYTES = 8; // 4-8 bytes (inclusive), min 5 recommended
		private static final int RANDOM_BYTES = 32; // 1-64 (inclusive), min 32 recommended
		private static final int COUNTER_BYTES = 2; // 1, 2, 4, or 8
		private static final AtomicInteger COUNTER_ID = new AtomicInteger(1);
	}
}

