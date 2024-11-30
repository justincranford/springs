package com.github.justincranford.springs.util.basic;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import lombok.AccessLevel;
import lombok.NoArgsConstructor;

@NoArgsConstructor(access=AccessLevel.PRIVATE)
public final class EnumUtils {
    public static <T extends Enum<T>> T valueOfCaseInsensitive(Class<T> enumClass, String value) {
        for (T enumConstant : enumClass.getEnumConstants()) {
            if (enumConstant.name().equalsIgnoreCase(value)) {
                return enumConstant;
            }
        }
        final List<String> values = Arrays.stream(enumClass.getEnumConstants()).map(T::name).toList();
        throw new IllegalArgumentException("No enum `" + value + "` in " + enumClass.getSimpleName() + "=" + StringUtil.toString("[", ", ", "]", values).toLowerCase() + ". See `" + enumClass.getCanonicalName() + "` for details.");
    }
}
