package com.github.justincranford.springs.persistenceorm.users.persona.email;

import java.util.regex.Pattern;

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;

public class EmailRfc5321Validator implements ConstraintValidator<EmailRfc5321, String> {
    private static final Pattern EMAIL_PATTERN = Pattern.compile("^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$");
    @Override
    public boolean isValid(final String email, final ConstraintValidatorContext context) {
    	return (email == null) || ((email.length() <= 254) && (EMAIL_PATTERN.matcher(email).matches()));
    }
}
