package com.github.justincranford.springs.util.basic;

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
        throw new IllegalArgumentException("No enum constant for value: " + value);
    }
}
