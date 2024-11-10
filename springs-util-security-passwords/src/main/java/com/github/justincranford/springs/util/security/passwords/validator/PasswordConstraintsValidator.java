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
@SuppressWarnings({"nls", "boxing"})
public class PasswordConstraintsValidator implements ConstraintValidator<PasswordConstraints, String> {
    private Set<Integer> uppers;
    private Set<Integer> lowers;
    private Set<Integer> digits;
    private Set<Integer> specials;
    private Set<Integer> whitespace;
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

    @Override
    public void initialize(final PasswordConstraints constraintAnnotation) {
        this.uppers     = constraintAnnotation.uppers().codePoints().boxed().collect(Collectors.toSet());
        this.lowers     = constraintAnnotation.lowers().codePoints().boxed().collect(Collectors.toSet());
        this.digits     = constraintAnnotation.digits().codePoints().boxed().collect(Collectors.toSet());
        this.specials   = constraintAnnotation.specials().codePoints().boxed().collect(Collectors.toSet());
        this.whitespace = constraintAnnotation.whitespace().codePoints().boxed().collect(Collectors.toSet());

        this.minLength = constraintAnnotation.minLength();
        this.maxLength = constraintAnnotation.maxLength();

        this.minUppers     = constraintAnnotation.minUppers();
        this.maxUppers     = constraintAnnotation.maxUppers();
        this.minLowers     = constraintAnnotation.minLowers();
        this.maxLowers     = constraintAnnotation.maxLowers();
        this.minDigits     = constraintAnnotation.minDigits();
        this.maxDigits     = constraintAnnotation.maxDigits();
        this.minSpecials   = constraintAnnotation.minSpecials();
        this.maxSpecials   = constraintAnnotation.maxSpecials();
        this.minWhitespace = constraintAnnotation.minWhitespace();
        this.maxWhitespace = constraintAnnotation.maxWhitespace();

        this.maxAnywhereRepeats    = constraintAnnotation.maxAnywhereRepeats();
        this.maxConsecutiveRepeats = constraintAnnotation.maxConsecutiveRepeats();
    }

	@Override
    public boolean isValid(final String password, final ConstraintValidatorContext context) {
        return isValidInternal(password, true); // throwException=false
    }

	private boolean isValidInternal(final String password, final boolean throwException) {
		if (password == null) {
			return throwOrFalse(throwException, "Password must not be null");
        } else if (password.length() < this.minLength) {
			return throwOrFalse(throwException, "Password violates minLength constraint: " + this.minLength);
        } else if (password.length() > this.maxLength) {
			return throwOrFalse(throwException, "Password violates maxLength constraint: " + this.maxLength);
        }
        final List<Integer> passwordCodePoints = password.codePoints().boxed().toList();

        int upperCount = 0, lowerCount = 0, digitCount = 0, specialCount = 0, whitespaceCount = 0, consecutiveRepeats = 0;
        final Map<Integer, Integer> anywhereRepeats = new HashMap<>();
        for (int i = 0; i < passwordCodePoints.size(); i++) {
            final Integer currentCodePoint = passwordCodePoints.get(i);
			if (this.uppers.contains(currentCodePoint)) {
                if (++upperCount > this.maxUppers) {
        			return throwOrFalse(throwException, "Password violates maxUppers constraint: " + this.maxUppers);
                }
            } else if (this.lowers.contains(currentCodePoint)) {
                if (++lowerCount > this.maxLowers) {
        			return throwOrFalse(throwException, "Password violates maxLowers constraint: " + this.maxLowers);
                }
            } else if (this.digits.contains(currentCodePoint)) {
                if (++digitCount > this.maxDigits) {
        			return throwOrFalse(throwException, "Password violates maxDigits constraint: " + this.maxDigits);
                }
            } else if (this.specials.contains(currentCodePoint)) {
                if (++specialCount > this.maxSpecials) {
        			return throwOrFalse(throwException, "Password violates maxSpecials constraint: " + this.maxSpecials);
                }
            } else if (this.whitespace.contains(currentCodePoint)) {
                if (++whitespaceCount > this.maxWhitespace) {
        			return throwOrFalse(throwException, "Password violates maxWhitespace constraint: " + this.maxWhitespace);
                }
            } // else some other UNICODE code point, and no other category constraint is applied

			final Integer oldAnywhereCount = anywhereRepeats.getOrDefault(currentCodePoint, Integer.valueOf(0));
			final Integer newAnywhereCount = Integer.valueOf(oldAnywhereCount + 1);
			if (i > 0) {
                if (newAnywhereCount > this.maxAnywhereRepeats) {
        			return throwOrFalse(throwException, "Password violates maxAnywhereRepeats constraint: " + this.maxAnywhereRepeats);
                }
				final Integer previousCodePoint = passwordCodePoints.get(i - 1);
				if (currentCodePoint.intValue() == previousCodePoint.intValue()) {
                    if (++consecutiveRepeats > this.maxConsecutiveRepeats) {
            			return throwOrFalse(throwException, "Password violates maxConsecutiveRepeats constraint: " + this.maxConsecutiveRepeats);
                    }
                } else {
                    consecutiveRepeats = 0;
                }
			}
			anywhereRepeats.put(currentCodePoint, newAnywhereCount);
        }
        if (upperCount < this.minUppers) {
			return throwOrFalse(throwException, "Password violates minUppers constraint: " + this.minUppers);
        } else if (upperCount < this.minLowers) {
			return throwOrFalse(throwException, "Password violates minUppers constraint: " + this.minLowers);
        } else if (upperCount < this.minDigits) {
			return throwOrFalse(throwException, "Password violates minUppers constraint: " + this.minDigits);
        } else if (upperCount < this.minSpecials) {
			return throwOrFalse(throwException, "Password violates minUppers constraint: " + this.minSpecials);
        } else if (upperCount < this.minWhitespace) {
			return throwOrFalse(throwException, "Password violates minUppers constraint: " + this.minWhitespace);
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

