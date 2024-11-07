package com.github.justincranford.springs.persistenceorm.clients.client;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import com.github.justincranford.springs.util.basic.SecureRandomUtil;

@SuppressWarnings({"nls"})
public class PasswordGenerator {
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
