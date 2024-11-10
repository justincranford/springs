package com.github.justincranford.springs.util.security.passwords.validator;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import com.github.justincranford.springs.util.security.passwords.constraints.PasswordConstraints;

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@SuppressWarnings({"nls"})
public class PasswordConstraintsValidator implements ConstraintValidator<PasswordConstraints, String> {
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
    public void initialize(final PasswordConstraints constraintAnnotation) {
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
        return isValidInternal(password, true); // throwException=false
    }

	private boolean isValidInternal(final String password, final boolean throwException) {
		if (password == null) {
			return throwOrFalse(throwException, "Password must not be null");
        } else if (password.length() < this.minLength) {
			return throwOrFalse(throwException, "Password " + password + " violates minLength constraint: " + this.minLength);
        } else if (password.length() > this.maxLength) {
			return throwOrFalse(throwException, "Password " + password + " violates maxLength constraint: " + this.maxLength);
        }
        final List<Integer> passwordCodePoints = password.codePoints().boxed().toList();

        int upperCount = 0, lowerCount = 0, numberCount = 0, specialCount = 0, whitespaceCount = 0, consecutiveRepeats = 0;
        final Map<Integer, Integer> anywhereRepeats = new HashMap<>();
        for (int i = 0; i < passwordCodePoints.size(); i++) {
            final Integer currentCodePoint = passwordCodePoints.get(i);
			if (Character.isUpperCase(currentCodePoint.intValue())) {
                if (++upperCount > this.maxUppers) {
        			return throwOrFalse(throwException, "Password " + password + " violates maxUppers constraint: " + this.maxUppers);
                }
            } else if (Character.isLowerCase(currentCodePoint.intValue())) {
                if (++lowerCount > this.maxLowers) {
        			return throwOrFalse(throwException, "Password " + password + " violates maxLowers constraint: " + this.maxLowers);
                }
            } else if (Character.isDigit(currentCodePoint.intValue())) {
                if (++numberCount > this.maxDigits) {
        			return throwOrFalse(throwException, "Password " + password + " violates maxDigits constraint: " + this.maxDigits);
                }
            } else if (this.specials.contains(currentCodePoint)) {
                if (++specialCount > this.maxSpecials) {
        			return throwOrFalse(throwException, "Password " + password + " violates maxSpecials constraint: " + this.maxSpecials);
                }
            } else if (Character.isWhitespace(currentCodePoint.intValue())) {
                if (++whitespaceCount > this.maxWhitespace) {
        			return throwOrFalse(throwException, "Password " + password + " violates maxWhitespace constraint: " + this.maxWhitespace);
                }
            } // else some other UNICODE code point, and no other category constraint is applied

			final Integer oldAnywhereCount = anywhereRepeats.getOrDefault(currentCodePoint, Integer.valueOf(0));
			final Integer newAnywhereCount = Integer.valueOf(oldAnywhereCount.intValue() + 1);
			if (i > 0) {
                if (newAnywhereCount.intValue() > this.maxAnywhereRepeats) {
        			return throwOrFalse(throwException, "Password " + password + " violates maxAnywhereRepeats constraint: " + this.maxAnywhereRepeats);
                }
				final Integer previousCodePoint = passwordCodePoints.get(i - 1);
				if (currentCodePoint.intValue() == previousCodePoint.intValue()) {
                    if (++consecutiveRepeats > this.maxConsecutiveRepeats) {
            			return throwOrFalse(throwException, "Password " + password + " violates maxConsecutiveRepeats constraint: " + this.maxConsecutiveRepeats);
                    }
                } else {
                    consecutiveRepeats = 0;
                }
			}
			anywhereRepeats.put(currentCodePoint, newAnywhereCount);
        }
        if (upperCount < this.minUppers) {
			return throwOrFalse(throwException, "Password " + password + " violates minUppers constraint: " + this.minUppers);
        } else if (upperCount < this.minLowers) {
			return throwOrFalse(throwException, "Password " + password + " violates minUppers constraint: " + this.minLowers);
        } else if (upperCount < this.minDigits) {
			return throwOrFalse(throwException, "Password " + password + " violates minUppers constraint: " + this.minDigits);
        } else if (upperCount < this.minSpecials) {
			return throwOrFalse(throwException, "Password " + password + " violates minUppers constraint: " + this.minSpecials);
        } else if (upperCount < this.minWhitespace) {
			return throwOrFalse(throwException, "Password " + password + " violates minUppers constraint: " + this.minWhitespace);
        }
        return true;
	}

	private static boolean throwOrFalse(final boolean throwException, final String msg) {
		log.error(msg);
		if (throwException) {
			throw new RuntimeException(msg);
		}
		return false;
	}
}

