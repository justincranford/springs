package com.github.justincranford.springs.util.security.passwords;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;

public class PasswordStrengthValidator implements ConstraintValidator<PasswordStrength, String> {
    private int minLength;
    private int maxLength;
    private int minUppers;
    private int maxUppers;
    private int minLowers;
    private int maxLowers;
    private int minDigits;
    private int maxDigits;
    private int minSpecials;
    private int maxSpecials;
    private int minWhitespace;
    private int maxWhitespace;
    private int maxAnywhereRepeats;
    private int maxConsecutiveRepeats;
    private Set<Integer> specials;

    @Override
    public void initialize(final PasswordStrength constraintAnnotation) {
        this.minLength = constraintAnnotation.minLength();
        this.maxLength = constraintAnnotation.maxLength();
        this.minUppers = constraintAnnotation.minUppers();
        this.maxUppers = constraintAnnotation.maxUppers();
        this.minLowers = constraintAnnotation.minLowers();
        this.maxLowers = constraintAnnotation.maxLowers();
        this.minDigits = constraintAnnotation.minDigits();
        this.maxDigits = constraintAnnotation.maxDigits();
        this.minSpecials = constraintAnnotation.minSpecials();
        this.maxSpecials = constraintAnnotation.maxSpecials();
        this.minWhitespace = constraintAnnotation.minWhitespace();
        this.maxWhitespace = constraintAnnotation.maxWhitespace();
        this.maxAnywhereRepeats = constraintAnnotation.maxAnywhereRepeats();
        this.maxConsecutiveRepeats = constraintAnnotation.maxConsecutiveRepeats();
        this.specials = constraintAnnotation.specials().codePoints().boxed().collect(Collectors.toSet());
    }

    @Override
    public boolean isValid(final String password, final ConstraintValidatorContext context) {
        if (password == null) {
            return false;
        } else if (password.length() < this.minLength || password.length() > this.maxLength) {
            return false;
        }
        final List<Integer> passwordCodePoints = password.codePoints().boxed().toList();

        int upperCount = 0, lowerCount = 0, numberCount = 0, specialCount = 0, whitespaceCount = 0, consecutiveRepeats = 0;
        final Map<Integer, Integer> anywhereRepeats = new HashMap<>();
        for (int i = 0; i < passwordCodePoints.size(); i++) {
            final Integer currentCodePoint = passwordCodePoints.get(i);
			if (Character.isUpperCase(currentCodePoint.intValue())) {
                if (++upperCount > this.maxUppers) {
                	return false;
                }
            } else if (Character.isLowerCase(currentCodePoint.intValue())) {
                if (++lowerCount > this.maxLowers) {
                	return false;
                }
            } else if (Character.isDigit(currentCodePoint.intValue())) {
                if (++numberCount > this.maxDigits) {
                	return false;
                }
            } else if (this.specials.contains(currentCodePoint)) {
                if (++specialCount > this.maxSpecials) {
                	return false;
                }
            } else if (Character.isWhitespace(currentCodePoint.intValue())) {
                if (++whitespaceCount > this.maxWhitespace) {
                	return false;
                }
            } // else some other UNICODE code point, and no other category constraint is applied

			final Integer oldAnywhereCount = anywhereRepeats.getOrDefault(currentCodePoint, Integer.valueOf(0));
			final Integer newAnywhereCount = Integer.valueOf(oldAnywhereCount.intValue() + 1);
			if (i > 0) {
                if (newAnywhereCount.intValue() > this.maxAnywhereRepeats) {
                    return false;
                }
				final Integer previousCodePoint = passwordCodePoints.get(i - 1);
				if (currentCodePoint.intValue() == previousCodePoint.intValue()) {
                    if (++consecutiveRepeats > this.maxConsecutiveRepeats) {
                        return false;
                    }
                } else {
                    consecutiveRepeats = 0;
                }
			}
			anywhereRepeats.put(currentCodePoint, newAnywhereCount);
        }
        return upperCount >= this.minUppers &&
               lowerCount >= this.minLowers &&
               numberCount >= this.minDigits &&
               specialCount >= this.minSpecials &&
               whitespaceCount >= this.minWhitespace;
    }
}

