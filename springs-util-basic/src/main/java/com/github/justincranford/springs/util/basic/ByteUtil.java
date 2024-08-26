package com.github.justincranford.springs.util.basic;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

public class ByteUtil {
	public static byte[] byteArray(final int integer) {
		return ByteBuffer.allocate(4).order(ByteOrder.BIG_ENDIAN).putInt(integer).array();
	}
}
