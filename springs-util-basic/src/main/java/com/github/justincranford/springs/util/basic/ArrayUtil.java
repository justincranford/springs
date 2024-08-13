package com.github.justincranford.springs.util.basic;

import java.lang.reflect.Array;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.stream.IntStream;

public class ArrayUtil {
	public static <O> O firstOrNull(final O[] array) {
		return (array != null) && (array.length > 0) ? array[0] : null;
	}

	public static byte[] concat(final byte[]... byteArrays) {
	    final int concatLength = Arrays.stream(byteArrays).mapToInt(byteArray -> byteArray.length).sum();
		final ByteBuffer byteBuffer = ByteBuffer.allocate(concatLength);
	    Arrays.stream(byteArrays).forEach(byteArray -> byteBuffer.put(byteArray));
	    return byteBuffer.array();
	}

	@SuppressWarnings("unchecked")
	@SafeVarargs
	public static <O> O[] array(final O... array) {
		if ((array == null) || (array.length == 0)) {
			return array;
		}
		return array((Class<O>) array[0].getClass(), array); // use the class of first element to create the correct typed array
	}

	@SuppressWarnings("unchecked")
	@SafeVarargs
	public static <O> O[] array(final Class<O> clazz, final O... array) {
		if (array == null) {
			return null;
		}
		final O[] typedArray = (O[]) Array.newInstance(clazz, array.length); // instantiate the array with the submitted type
		IntStream.range(0, array.length).forEach(i -> typedArray[i] = array[i]); // copy Object[] array elements to the typed O[] array
		return typedArray;
	}
}
