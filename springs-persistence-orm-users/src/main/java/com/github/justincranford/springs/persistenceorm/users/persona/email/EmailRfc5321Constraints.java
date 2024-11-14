package com.github.justincranford.springs.persistenceorm.users.persona.email;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import jakarta.validation.Constraint;
import jakarta.validation.Payload;

@Documented
@Constraint(validatedBy = EmailRfc5321Validator.class)
@Target({ElementType.METHOD, ElementType.FIELD})
@Retention(RetentionPolicy.RUNTIME)
public @interface EmailRfc5321Constraints {
    String message() default "Email address must conform to RFC 5321 format (e.g. max 3-254 chars)";
    Class<?>[] groups() default {};
    Class<? extends Payload>[] payload() default {};
}
