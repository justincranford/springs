package com.github.justincranford.springs.util.security.passwords.constraints;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import com.github.justincranford.springs.util.security.passwords.validator.PasswordConstraintsValidator;

import jakarta.validation.Constraint;
import jakarta.validation.Payload;

@Documented
@Constraint(validatedBy = PasswordConstraintsValidator.class)
@Target({ElementType.METHOD, ElementType.FIELD})
@Retention(RetentionPolicy.RUNTIME)
public @interface PasswordConstraints {
    String message() default "Password does not meet required password constraints";
    Class<?>[] groups() default {};
    Class<? extends Payload>[] payload() default {};

    String firsts() default PasswordConstraintsValues.FIRSTS_DEFAULT;
    String uppers() default PasswordConstraintsValues.UPPERS_DEFAULT;
    String lowers() default PasswordConstraintsValues.LOWERS_DEFAULT;
    String digits() default PasswordConstraintsValues.DIGITS_DEFAULT;
    String specials() default PasswordConstraintsValues.SPECIALS_DEFAULT;
    String whitespace() default PasswordConstraintsValues.WHITESPACE_DEFAULT;

    int minLength() default PasswordConstraintsValues.MIN_LENGTH_DEFAULT;
    int maxLength() default PasswordConstraintsValues.MAX_LENGTH_DEFAULT;
    int minUppers() default PasswordConstraintsValues.MIN_UPPERS_DEFAULT;
    int maxUppers() default PasswordConstraintsValues.MAX_UPPERS_DEFAULT;
    int minLowers() default PasswordConstraintsValues.MIN_LOWERS_DEFAULT;
    int maxLowers() default PasswordConstraintsValues.MAX_LOWERS_DEFAULT;
    int minDigits() default PasswordConstraintsValues.MIN_DIGITS_DEFAULT;
    int maxDigits() default PasswordConstraintsValues.MAX_DIGITS_DEFAULT;
    int minSpecials() default PasswordConstraintsValues.MIN_SPECIALS_DEFAULT;
    int maxSpecials() default PasswordConstraintsValues.MAX_SPECIALS_DEFAULT;
    int minWhitespace() default PasswordConstraintsValues.MIN_WHITESPACE_DEFAULT;
    int maxWhitespace() default PasswordConstraintsValues.MAX_WHITESPACE_DEFAULT;
    int maxAnywhereRepeats() default PasswordConstraintsValues.MAX_ANYWHERE_REPEATS_DEFAULT;
    int maxConsecutiveRepeats() default PasswordConstraintsValues.MAX_CONSECUTIVE_REPEATS_DEFAULT;
}
