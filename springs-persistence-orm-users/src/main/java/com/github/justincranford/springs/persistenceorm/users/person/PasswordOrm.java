package com.github.justincranford.springs.persistenceorm.users.person;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.github.justincranford.springs.util.basic.SecureRandomUtil;

import jakarta.persistence.Column;
import jakarta.persistence.Embeddable;
import jakarta.validation.Constraint;
import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;
import jakarta.validation.Payload;
import jakarta.validation.constraints.Null;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;
import lombok.experimental.Accessors;

@Embeddable
@Getter(onMethod=@__(@JsonProperty))
@Setter
@ToString(callSuper=true)
@Builder(toBuilder=true)
@NoArgsConstructor
@AllArgsConstructor
@Accessors(fluent=true)
@SuppressWarnings({"nls"})
public class PasswordOrm {
    @PasswordStrength
    @Column(length=64)
    @Size(min=8,max=64)
//    @Null
    private String password;

    @Documented
    @Constraint(validatedBy = PasswordStrengthValidator.class)
    @Target({ElementType.METHOD, ElementType.FIELD})
    @Retention(RetentionPolicy.RUNTIME)
    public static @interface PasswordStrength {
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

    public static class PasswordStrengthValidator implements ConstraintValidator<PasswordStrength, String> {
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

    public static class PasswordGenerator {
		private static final List<Integer> UPPERCASE = "ABCDEFGHIJKLMNOPQRSTUVWXYZ".codePoints().boxed().toList();
        private static final List<Integer> LOWERCASE = "abcdefghijklmnopqrstuvwxyz".codePoints().boxed().toList();
        private static final List<Integer> DIGITS = "0123456789".codePoints().boxed().toList();
        private static final List<Integer> WHITESPACE = " \t\n\r\f".codePoints().boxed().toList();

        public static String generatePassword(final PasswordStrength constraintsAnnotation) {
			if (constraintsAnnotation.maxLength() < constraintsAnnotation.minLength()) {
				throw new IllegalArgumentException("Max length must be greater than or equal to min");
			} else if (constraintsAnnotation.maxUppers() < constraintsAnnotation.minUppers()) {
				throw new IllegalArgumentException("Max uppers must be greater than or equal to min");
			} else if (constraintsAnnotation.maxLowers() < constraintsAnnotation.minLowers()) {
				throw new IllegalArgumentException("Max lowers must be greater than or equal to min");
			} else if (constraintsAnnotation.maxDigits() < constraintsAnnotation.minDigits()) {
				throw new IllegalArgumentException("Max digits must be greater than or equal to min");
			} else if (constraintsAnnotation.maxSpecials() < constraintsAnnotation.minSpecials()) {
				throw new IllegalArgumentException("Max specials must be greater than or equal to min");
			} else if (constraintsAnnotation.maxWhitespace() < constraintsAnnotation.minWhitespace()) {
				throw new IllegalArgumentException("Max whitespace must be greater than or equal to min");
			} else if (constraintsAnnotation.maxAnywhereRepeats() < 0) {
				throw new IllegalArgumentException("Max anywhere repeats must be greater than zero");
			} else if (constraintsAnnotation.maxConsecutiveRepeats() < 1) {
				throw new IllegalArgumentException("Max consecutive repeats must be greater than one");
			}

			final Integer maxAnywhereRepeats = Integer.valueOf(constraintsAnnotation.maxAnywhereRepeats());
			final Map<Integer, Integer> availableUppersAndCounts     =  UPPERCASE.stream().collect(Collectors.toMap(codePoint -> codePoint, codePoint -> maxAnywhereRepeats));
			final Map<Integer, Integer> availableLowersAndCounts     =  LOWERCASE.stream().collect(Collectors.toMap(codePoint -> codePoint, codePoint -> maxAnywhereRepeats));
            final Map<Integer, Integer> availableDigitsAndCounts     =     DIGITS.stream().collect(Collectors.toMap(codePoint -> codePoint, codePoint -> maxAnywhereRepeats));
            final Map<Integer, Integer> availableWhitespaceAndCounts = WHITESPACE.stream().collect(Collectors.toMap(codePoint -> codePoint, codePoint -> maxAnywhereRepeats));
            final Map<Integer, Integer> availableSpecialsAndCounts   = constraintsAnnotation.specials().codePoints().boxed().collect(Collectors.toMap(codePoint -> codePoint, codePoint -> maxAnywhereRepeats));

			final Map<Integer, Integer> selectedCodePointsAndCounts = new HashMap<>();
			selectCharacters(selectedCodePointsAndCounts, availableUppersAndCounts,     constraintsAnnotation.minUppers());
			selectCharacters(selectedCodePointsAndCounts, availableLowersAndCounts,     constraintsAnnotation.minLowers());
			selectCharacters(selectedCodePointsAndCounts, availableDigitsAndCounts,     constraintsAnnotation.minDigits());
			selectCharacters(selectedCodePointsAndCounts, availableSpecialsAndCounts,   constraintsAnnotation.minSpecials());
			selectCharacters(selectedCodePointsAndCounts, availableWhitespaceAndCounts, constraintsAnnotation.minWhitespace());

			final int selectedCodePointsTotal = selectedCodePointsAndCounts.values().stream().reduce(Integer.valueOf(0), Integer::sum).intValue();
	        if (selectedCodePointsTotal < constraintsAnnotation.minLength()) {
	            throw new IllegalArgumentException("Minimum constraints exceed minimum length; minimum length is too small");
	        } else if (selectedCodePointsTotal > constraintsAnnotation.maxLength()) {
	            throw new IllegalArgumentException("Minimum constraints exceed maximum length; maximum length is too small");
	        }

			final Map<Integer, Integer> availableCodePointsAndCounts = new HashMap<>();
            if (constraintsAnnotation.maxUppers()     > constraintsAnnotation.minUppers()) availableCodePointsAndCounts.putAll(availableUppersAndCounts);
            if (constraintsAnnotation.maxLowers()     > constraintsAnnotation.minLowers()) availableCodePointsAndCounts.putAll(availableLowersAndCounts);
            if (constraintsAnnotation.maxDigits()     > constraintsAnnotation.minDigits()) availableCodePointsAndCounts.putAll(availableDigitsAndCounts);
            if (constraintsAnnotation.maxSpecials()   > constraintsAnnotation.minSpecials()) availableCodePointsAndCounts.putAll(availableSpecialsAndCounts);
            if (constraintsAnnotation.maxWhitespace() > constraintsAnnotation.minWhitespace()) availableCodePointsAndCounts.putAll(availableWhitespaceAndCounts);
            if (availableCodePointsAndCounts.isEmpty()) {
            	throw new IllegalArgumentException("No available code points remaining");
            }

	        final int totalCodePoints     = SecureRandomUtil.SECURE_RANDOM.nextInt(constraintsAnnotation.minDigits(), constraintsAnnotation.maxDigits() + 1);
			final int remainingCodePoints = totalCodePoints - selectedCodePointsAndCounts.size();
			if (remainingCodePoints > 0) {
				selectCharacters(availableCodePointsAndCounts, availableCodePointsAndCounts, remainingCodePoints);
			}

	        final List<Integer> selectedCodePoints = new ArrayList<>(selectedCodePointsAndCounts.values());
			Collections.shuffle(selectedCodePoints);
	        final StringBuilder passwordBuilder = new StringBuilder(totalCodePoints);
	        for (final Integer selectedCodePoint : selectedCodePoints) {
	            passwordBuilder.append(Character.toChars(selectedCodePoint.intValue()));
	        }
	        return passwordBuilder.toString();
        }

        private static void selectCharacters(
    		final Map<Integer, Integer> selectedCodePointsAndCounts,
    		final Map<Integer, Integer> availableCodePointsAndCounts,
    		final int requiredCodePointCount
		) {
        	final int availableCodePointTotal = availableCodePointsAndCounts.values().stream().reduce(Integer.valueOf(0), Integer::sum).intValue();
        	if (requiredCodePointCount > availableCodePointTotal) {
        		throw new IllegalArgumentException("Insufficient remaining code points total remaining");
        	}
        	final List<Integer> availableCodePoints = new ArrayList<>(availableCodePointsAndCounts.keySet());
        	for (int i = 0; i < requiredCodePointCount; i++) {
        		final Integer nextCodePoint = availableCodePoints.get(SecureRandomUtil.SECURE_RANDOM.nextInt(availableCodePoints.size()));

        		// decrement available code point count; remove code point and count, if decrementing will result in a count of 0
        		final Integer availableCodePointCount = availableCodePointsAndCounts.get(nextCodePoint);
				if (availableCodePointCount.intValue() == 1) {
					availableCodePointsAndCounts.remove(nextCodePoint);
					availableCodePoints.remove(nextCodePoint);
				} else {
					availableCodePointsAndCounts.put(nextCodePoint, Integer.valueOf(availableCodePointCount.intValue() - 1));
				}

				// increment the selected code point count; add code count if not present and set to 1
        		final Integer selectedCodePointCount = selectedCodePointsAndCounts.get(nextCodePoint);
        		if (selectedCodePointCount == null) {
            		selectedCodePointsAndCounts.put(nextCodePoint, Integer.valueOf(1));
        		} else {
            		selectedCodePointsAndCounts.put(nextCodePoint, Integer.valueOf(selectedCodePointCount.intValue() + 1));
        		}
            }
        }
    }
}
