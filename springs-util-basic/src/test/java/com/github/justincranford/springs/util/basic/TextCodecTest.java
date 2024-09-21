package com.github.justincranford.springs.util.basic;

import static com.github.justincranford.springs.util.basic.TextCodec.HEX_LC_LENIENT;
import static com.github.justincranford.springs.util.basic.TextCodec.HEX_LC_STRICT;
import static com.github.justincranford.springs.util.basic.TextCodec.HEX_UC_LENIENT;
import static com.github.justincranford.springs.util.basic.TextCodec.HEX_UC_STRICT;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import com.github.justincranford.springs.util.basic.TextCodec.HexCodec;

@SuppressWarnings({"nls"})
public class TextCodecTest {
    private static final byte[] EMPTY_BYTES = { };
    private static final String EMPTY_STRING = "";

    @Nested
    public class HexCodexTests {
        private static final byte[] UNENCODED_BYTES = {0x0A, 0x1B, 0x2C, 0x3D, 0x4E, 0x5F, 0x67, (byte) 0x89};
        private static final String ENCODED_STRING_MIXED_CASE = "0A1b2C3d4E5f6789";
        private static final String ENCODED_STRING_UPPER_CASE = ENCODED_STRING_MIXED_CASE.toUpperCase();
        private static final String ENCODED_STRING_LOWER_CASE = ENCODED_STRING_MIXED_CASE.toLowerCase();

        @Test
        void testUcStrict() {
    		verifyEncodeSuccess(HEX_UC_STRICT, UNENCODED_BYTES, ENCODED_STRING_UPPER_CASE);
    		verifyDecodeSuccess(HEX_UC_STRICT, ENCODED_STRING_UPPER_CASE, UNENCODED_BYTES);
    		verifyStrictDecodeFail(HEX_UC_STRICT, ENCODED_STRING_LOWER_CASE);
    		verifyStrictDecodeFail(HEX_UC_STRICT, ENCODED_STRING_MIXED_CASE);
    		verifyUnevenFail(HEX_UC_STRICT);
    		verifyNullFail(HEX_UC_STRICT);

    		verifyEncodeSuccess(HEX_UC_STRICT, EMPTY_BYTES, EMPTY_STRING);
    		verifyDecodeSuccess(HEX_UC_STRICT, EMPTY_STRING, EMPTY_BYTES);
        }

        @Test
        void testUcLenient() {
    		verifyEncodeSuccess(HEX_UC_LENIENT, UNENCODED_BYTES, ENCODED_STRING_UPPER_CASE);
    		verifyDecodeSuccess(HEX_UC_LENIENT, ENCODED_STRING_UPPER_CASE, UNENCODED_BYTES);
    		verifyDecodeSuccess(HEX_UC_LENIENT, ENCODED_STRING_LOWER_CASE, UNENCODED_BYTES);
    		verifyDecodeSuccess(HEX_UC_LENIENT, ENCODED_STRING_MIXED_CASE, UNENCODED_BYTES);
    		verifyUnevenFail(HEX_UC_LENIENT);
    		verifyNullFail(HEX_UC_LENIENT);

    		verifyEncodeSuccess(HEX_UC_LENIENT, EMPTY_BYTES, EMPTY_STRING);
    		verifyDecodeSuccess(HEX_UC_LENIENT, EMPTY_STRING, EMPTY_BYTES);
        }

        @Test
        void testLcStrict() {
    		verifyEncodeSuccess(HEX_LC_STRICT, UNENCODED_BYTES, ENCODED_STRING_LOWER_CASE);
    		verifyDecodeSuccess(HEX_LC_STRICT, ENCODED_STRING_LOWER_CASE, UNENCODED_BYTES);
    		verifyStrictDecodeFail(HEX_LC_STRICT, ENCODED_STRING_UPPER_CASE);
    		verifyStrictDecodeFail(HEX_LC_STRICT, ENCODED_STRING_MIXED_CASE);
    		verifyUnevenFail(HEX_LC_STRICT);
    		verifyNullFail(HEX_LC_STRICT);

    		verifyEncodeSuccess(HEX_LC_STRICT, EMPTY_BYTES, EMPTY_STRING);
    		verifyDecodeSuccess(HEX_LC_STRICT, EMPTY_STRING, EMPTY_BYTES);
        }

        @Test
        void testLcLenient() {
    		verifyEncodeSuccess(HEX_LC_LENIENT, UNENCODED_BYTES, ENCODED_STRING_LOWER_CASE);
    		verifyDecodeSuccess(HEX_LC_LENIENT, ENCODED_STRING_LOWER_CASE, UNENCODED_BYTES);
    		verifyDecodeSuccess(HEX_LC_LENIENT, ENCODED_STRING_LOWER_CASE, UNENCODED_BYTES);
    		verifyDecodeSuccess(HEX_LC_LENIENT, ENCODED_STRING_MIXED_CASE, UNENCODED_BYTES);
    		verifyUnevenFail(HEX_LC_LENIENT);
    		verifyNullFail(HEX_LC_LENIENT);

    		verifyEncodeSuccess(HEX_LC_LENIENT, EMPTY_BYTES, EMPTY_STRING);
    		verifyDecodeSuccess(HEX_LC_LENIENT, EMPTY_STRING, EMPTY_BYTES);
        }

    	private static void verifyEncodeSuccess(final HexCodec hexEncDec, final byte[] unencodedBytes, final String encodedString) {
    		assertEquals(encodedString, hexEncDec.encodeToString(unencodedBytes));
            assertArrayEquals(encodedString.getBytes(StandardCharsets.UTF_8), hexEncDec.encodeToBytes(unencodedBytes));
        }

    	private void verifyDecodeSuccess(final HexCodec hexEncDec, final String encodedString, final byte[] unencodedBytes) {
    		assertArrayEquals(unencodedBytes, hexEncDec.decodeFromBytes(encodedString.getBytes(StandardCharsets.UTF_8)));
            assertArrayEquals(unencodedBytes, hexEncDec.decodeFromString(encodedString));
    	}

    	private void verifyStrictDecodeFail(final HexCodec hexEncDec, final String encodedString) {
    		final IllegalArgumentException exception2 = assertThrows(IllegalArgumentException.class, () -> hexEncDec.decodeFromString(encodedString));
    		assertEquals("Invalid character, expected hex character", exception2.getMessage());
    		final IllegalArgumentException exception1 = assertThrows(IllegalArgumentException.class, () -> hexEncDec.decodeFromBytes(encodedString.getBytes(StandardCharsets.UTF_8)));
    		assertEquals("Invalid character, expected hex character", exception1.getMessage());
    	}

    	private void verifyUnevenFail(final HexCodec hexEncDec) {
    		final IllegalArgumentException exception2 = assertThrows(IllegalArgumentException.class, () -> hexEncDec.decodeFromString("0"));
    		assertEquals("Input must have even length", exception2.getMessage());
    		final IllegalArgumentException exception1 = assertThrows(IllegalArgumentException.class, () -> hexEncDec.decodeFromBytes("0".getBytes(StandardCharsets.UTF_8)));
    		assertEquals("Input must have even length", exception1.getMessage());
    	}

    	private void verifyNullFail(final HexCodec hexEncDec) {
    		final NullPointerException exception1 = assertThrows(NullPointerException.class, () -> hexEncDec.encodeToString(null));
    		assertEquals("Bytes must be non-null", exception1.getMessage());
    		final NullPointerException exception2 = assertThrows(NullPointerException.class, () -> hexEncDec.decodeFromString(null));
    		assertEquals("String must be non-null", exception2.getMessage());
    		final NullPointerException exception3 = assertThrows(NullPointerException.class, () -> hexEncDec.encodeToBytes(null));
    		assertEquals("Bytes must be non-null", exception3.getMessage());
    		final NullPointerException exception4 = assertThrows(NullPointerException.class, () -> hexEncDec.decodeFromBytes(null));
    		assertEquals("Bytes must be non-null", exception4.getMessage());
    	}
    }
}
