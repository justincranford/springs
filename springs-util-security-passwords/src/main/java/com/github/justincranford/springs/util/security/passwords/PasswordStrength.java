package com.github.justincranford.springs.util.security.passwords;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import com.github.justincranford.springs.util.security.passwords.properties.SpringsUtilSecurityPasswordsProperties.Constraints;

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
    int minLength() default Constraints.MIN_LENGTH_DEFAULT;
    int maxLength() default Constraints.MAX_LENGTH_DEFAULT;
    int minUppers() default Constraints.MIN_UPPERS_DEFAULT;
    int maxUppers() default Constraints.MAX_UPPERS_DEFAULT;
    int minLowers() default Constraints.MIN_LOWERS_DEFAULT;
    int maxLowers() default Constraints.MAX_LOWERS_DEFAULT;
    int minDigits() default Constraints.MIN_DIGITS_DEFAULT;
    int maxDigits() default Constraints.MAX_DIGITS_DEFAULT;
    int minSpecials() default Constraints.MIN_SPECIALS_DEFAULT;
    int maxSpecials() default Constraints.MAX_SPECIALS_DEFAULT;
    int minWhitespace() default Constraints.MIN_WHITESPACE_DEFAULT;
    int maxWhitespace() default Constraints.MAX_WHITESPACE_DEFAULT;
    int maxAnywhereRepeats() default Constraints.MAX_ANYWHERE_REPEATS_DEFAULT;
    int maxConsecutiveRepeats() default Constraints.MAX_CONSECUTIVE_REPEATS_DEFAULT;
    String specials() default Constraints.SPECIALS_DEFAULT;
}
