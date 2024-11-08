package com.github.justincranford.springs.util.security.passwords;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import jakarta.validation.Constraint;
import jakarta.validation.Payload;

@Documented
@Constraint(validatedBy = PasswordStrengthValidator.class)
@Target({ElementType.METHOD, ElementType.FIELD})
@Retention(RetentionPolicy.RUNTIME)
public @interface PasswordStrength {
    String message() default "Password must meet strength requirements";
    Class<?>[] groups() default {};
    Class<? extends Payload>[] payload() default {};
    int minLength() default 8;
    int maxLength() default 64;
    int minUppers() default 1;
    int maxUppers() default Integer.MAX_VALUE;
    int minLowers() default 1;
    int maxLowers() default Integer.MAX_VALUE;
    int minDigits() default 1;
    int maxDigits() default Integer.MAX_VALUE;
    int minSpecials() default 1;
    int maxSpecials() default Integer.MAX_VALUE;
    int minWhitespace() default 0;
    int maxWhitespace() default Integer.MAX_VALUE;
    int maxAnywhereRepeats() default 3;
    int maxConsecutiveRepeats() default 2;
    String specials() default "~`!@#$%^&*()_-+={}[]|\\\"':;?/<>,.";
}
