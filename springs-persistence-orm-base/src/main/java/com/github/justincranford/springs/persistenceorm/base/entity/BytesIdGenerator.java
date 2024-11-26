package com.github.justincranford.springs.persistenceorm.base.entity;

import com.github.justincranford.springs.util.basic.SecureRandomUtil;
import com.github.justincranford.springs.util.basic.TextCodec;
import jakarta.validation.constraints.NotNull;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import java.nio.ByteBuffer;
import java.util.concurrent.atomic.AtomicInteger;

@RequiredArgsConstructor
@Slf4j
public class BytesIdGenerator {
	public static final int TOTAL_BYTES_LENGTH = Constants.USE_TIMESTAMP_AND_RANDOM_BYTES ? Constants.TIMESTAMP_BYTES + Constants.RANDOM_BYTES : Constants.COUNTER_BYTES;

	private final AtomicInteger counterId = new AtomicInteger(1);
	private final String name;

	public @NotNull byte[] generate() {
		if (Constants.USE_TIMESTAMP_AND_RANDOM_BYTES) {
			final byte[] bytes = SecureRandomUtil.timeStampBytesAndRandomBytes(Constants.TIMESTAMP_BYTES, Constants.RANDOM_BYTES);
			log.info("Generated {}, hex: 0x{}, base64url: {}, b64std: {}", this.name, TextCodec.HEX_UC_STRICT.encodeToString(bytes), TextCodec.B64_URL.encodeToString(bytes), TextCodec.B64_STD.encodeToString(bytes));
			return bytes;
		}

		final int id = this.counterId.getAndIncrement();
		final byte[] bytes = switch (TOTAL_BYTES_LENGTH) {
			case 1 -> ByteBuffer.allocate(TOTAL_BYTES_LENGTH).put((byte) id).array();
			case 2 -> ByteBuffer.allocate(TOTAL_BYTES_LENGTH).putShort((short) id).array();
			case 4 -> ByteBuffer.allocate(TOTAL_BYTES_LENGTH).putInt(id).array();
			case 8 -> ByteBuffer.allocate(TOTAL_BYTES_LENGTH).putLong(id).array();
			default -> throw new RuntimeException("Unsupported bytes length " + TOTAL_BYTES_LENGTH);
		};
		log.info("Generated {}, int: {}, hex: 0x{}, b64url: {}, b64std: {}", this.name, id, TextCodec.HEX_UC_STRICT.encodeToString(bytes), TextCodec.B64_URL.encodeToString(bytes), TextCodec.B64_STD.encodeToString(bytes));
		return bytes;
	}

	public static class Constants {
		private static final boolean USE_TIMESTAMP_AND_RANDOM_BYTES = false; // true recommended
		private static final int TIMESTAMP_BYTES = 8; // 4-8 bytes (inclusive), min 5 recommended
		private static final int RANDOM_BYTES = 32; // 1-64 (inclusive), min 32 recommended
		private static final int COUNTER_BYTES = 2; // 1, 2, 4, or 8
	}
}
