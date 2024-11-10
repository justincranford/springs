package com.github.justincranford.springs.util.security.passwords.generator;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.LinkedHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;

import com.github.justincranford.springs.util.basic.SecureRandomUtil;
import com.github.justincranford.springs.util.security.passwords.constraints.PasswordConstraints;

import lombok.extern.slf4j.Slf4j;

@Slf4j
@SuppressWarnings({"nls", "boxing"})
public class PasswordGenerator {
	private static final List<Integer> UPPERCASE = "ABCDEFGHIJKLMNOPQRSTUVWXYZ".codePoints().boxed().toList();
    private static final List<Integer> LOWERCASE = "abcdefghijklmnopqrstuvwxyz".codePoints().boxed().toList();
    private static final List<Integer> DIGITS = "0123456789".codePoints().boxed().toList();
    private static final List<Integer> WHITESPACE = " \t\n\r\f".codePoints().boxed().toList();

	private static final AtomicInteger X = new AtomicInteger(1);
	public static String generate(final PasswordConstraints passwordConstraints) {
		log.info("\n===================================\ngenerate test: {}", X.getAndIncrement());
		if (passwordConstraints.maxLength() < passwordConstraints.minLength()) {
			throw new IllegalArgumentException("Max length must be greater than or equal to min");
		} else if (passwordConstraints.maxUppers() < passwordConstraints.minUppers()) {
			throw new IllegalArgumentException("Max uppers must be greater than or equal to min");
		} else if (passwordConstraints.maxLowers() < passwordConstraints.minLowers()) {
			throw new IllegalArgumentException("Max lowers must be greater than or equal to min");
		} else if (passwordConstraints.maxDigits() < passwordConstraints.minDigits()) {
			throw new IllegalArgumentException("Max digits must be greater than or equal to min");
		} else if (passwordConstraints.maxSpecials() < passwordConstraints.minSpecials()) {
			throw new IllegalArgumentException("Max specials must be greater than or equal to min");
		} else if (passwordConstraints.maxWhitespace() < passwordConstraints.minWhitespace()) {
			throw new IllegalArgumentException("Max whitespace must be greater than or equal to min");
		} else if (passwordConstraints.maxAnywhereRepeats() < 0) {
			throw new IllegalArgumentException("Max anywhere repeats must be greater than zero");
		} else if (passwordConstraints.maxConsecutiveRepeats() < 1) {
			throw new IllegalArgumentException("Max consecutive repeats must be greater than one");
		}

		final AtomicInteger maxUppers          = new AtomicInteger(passwordConstraints.maxUppers());
		final AtomicInteger maxLowers          = new AtomicInteger(passwordConstraints.maxLowers());
		final AtomicInteger maxDigits          = new AtomicInteger(passwordConstraints.maxDigits());
		final AtomicInteger maxSpecials        = new AtomicInteger(passwordConstraints.maxSpecials());
		final AtomicInteger maxWhitespace      = new AtomicInteger(passwordConstraints.maxWhitespace());
		final int           maxAnywhereRepeats = passwordConstraints.maxAnywhereRepeats();
		final List<Integer> specials           = passwordConstraints.specials().codePoints().boxed().toList();
		final Map<Integer, List<AtomicInteger>> availableUppersAndCountsAndMax     =  UPPERCASE.stream().collect(Collectors.toMap(codePoint -> codePoint, codePoint -> List.of(new AtomicInteger(maxAnywhereRepeats), maxUppers),     (e1, e2) -> e1, LinkedHashMap::new));
		final Map<Integer, List<AtomicInteger>> availableLowersAndCountsAndMax     =  LOWERCASE.stream().collect(Collectors.toMap(codePoint -> codePoint, codePoint -> List.of(new AtomicInteger(maxAnywhereRepeats), maxLowers),     (e1, e2) -> e1, LinkedHashMap::new));
        final Map<Integer, List<AtomicInteger>> availableDigitsAndCountsAndMax     =     DIGITS.stream().collect(Collectors.toMap(codePoint -> codePoint, codePoint -> List.of(new AtomicInteger(maxAnywhereRepeats), maxDigits),     (e1, e2) -> e1, LinkedHashMap::new));
        final Map<Integer, List<AtomicInteger>> availableSpecialsAndCountsAndMax   =   specials.stream().collect(Collectors.toMap(codePoint -> codePoint, codePoint -> List.of(new AtomicInteger(maxAnywhereRepeats), maxSpecials),   (e1, e2) -> e1, LinkedHashMap::new));
        final Map<Integer, List<AtomicInteger>> availableWhitespaceAndCountsAndMax = WHITESPACE.stream().collect(Collectors.toMap(codePoint -> codePoint, codePoint -> List.of(new AtomicInteger(maxAnywhereRepeats), maxWhitespace), (e1, e2) -> e1, LinkedHashMap::new));

		final List<Integer> selectedCodePoints = new ArrayList<>();
		selectCharacters(selectedCodePoints, availableUppersAndCountsAndMax,     passwordConstraints.minUppers(),     specials);
		selectCharacters(selectedCodePoints, availableLowersAndCountsAndMax,     passwordConstraints.minLowers(),     specials);
		selectCharacters(selectedCodePoints, availableDigitsAndCountsAndMax,     passwordConstraints.minDigits(),     specials);
		selectCharacters(selectedCodePoints, availableSpecialsAndCountsAndMax,   passwordConstraints.minSpecials(),   specials);
		selectCharacters(selectedCodePoints, availableWhitespaceAndCountsAndMax, passwordConstraints.minWhitespace(), specials);

    	if (selectedCodePoints.size() > passwordConstraints.maxLength()) {
            throw new IllegalArgumentException("Minimum constraints exceed maximum length; maximum length is too small");
        }

        final int totalCodePoints     = 128;//SecureRandomUtil.SECURE_RANDOM.nextInt(passwordConstraints.minLength(), passwordConstraints.maxLength());
		final int remainingCodePoints = totalCodePoints - selectedCodePoints.size();
		if (remainingCodePoints > 0) {
			final Map<Integer, List<AtomicInteger>> availableCodePointsAndCounts = new LinkedHashMap<>();
	    	availableCodePointsAndCounts.putAll(availableUppersAndCountsAndMax);
	    	availableCodePointsAndCounts.putAll(availableLowersAndCountsAndMax);
	    	availableCodePointsAndCounts.putAll(availableDigitsAndCountsAndMax);
	    	availableCodePointsAndCounts.putAll(availableSpecialsAndCountsAndMax);
	    	availableCodePointsAndCounts.putAll(availableWhitespaceAndCountsAndMax);

			selectCharacters(selectedCodePoints, availableCodePointsAndCounts, remainingCodePoints, specials);
		}

		log.info("selectedCodePoints: {}", selectedCodePoints);
		Collections.shuffle(selectedCodePoints);
		log.info("shuffled selectedCodePoints: {}\n", selectedCodePoints);
        return toString(selectedCodePoints);
    }

	private static String toString(final Integer selectedCodePoint) {
		return new String(Character.toChars(selectedCodePoint.intValue()));
    }

	private static String toString(final List<Integer> selectedCodePoints) {
		final StringBuilder passwordBuilder = new StringBuilder(selectedCodePoints.size());
        for (final Integer selectedCodePoint : selectedCodePoints) {
            passwordBuilder.append(Character.toChars(selectedCodePoint.intValue()));
        }
        return passwordBuilder.toString();
	}

    private static void selectCharacters(
		final List<Integer> selectedCodePoints,
		final Map<Integer, List<AtomicInteger>> availableCodePointsAndCounts,
		final int numCodePointsRequested,
		final List<Integer> specials
	) {
		long numUppers     = selectedCodePoints.stream().filter(c -> UPPERCASE.contains(c)).count();
		long numLowers     = selectedCodePoints.stream().filter(c -> LOWERCASE.contains(c)).count();
		long numDigits     = selectedCodePoints.stream().filter(c -> DIGITS.contains(c)).count();
		long numSpecials   = selectedCodePoints.stream().filter(c -> specials.contains(c)).count();
		long numWhitespace = selectedCodePoints.stream().filter(c -> WHITESPACE.contains(c)).count();
    	log.info("numCodePointsRequested: {}", numCodePointsRequested);
    	log.info("selectedCodePoints:           size: {}, uppers: {}, lowers: {}, digits: {}, specials: {}, whitespace: {}, ints: {}, chars: \"{}\"", selectedCodePoints.size(), numUppers, numLowers, numDigits, numSpecials, numWhitespace, selectedCodePoints, toString(selectedCodePoints));
    	log.info("availableCodePointsAndCounts: size: {}, ints: {}", availableCodePointsAndCounts.size(), availableCodePointsAndCounts);
    	if (numCodePointsRequested <= 0) {
        	log.info("skip because no count requested, numCodePointsRequested: {}", numCodePointsRequested);
        	System.out.print('\n');
    		return;
    	}
    	final int totalIndividualCodePointsAvailable = availableCodePointsAndCounts.values().stream().map(listOfNumbers -> Integer.valueOf(listOfNumbers.get(0).intValue())).reduce(Integer.valueOf(0), Integer::sum).intValue();
    	if (numCodePointsRequested > totalIndividualCodePointsAvailable) {
    		throw new IllegalArgumentException("Insufficient code points available " + totalIndividualCodePointsAvailable + " for request " + numCodePointsRequested + ".");
    	}
    	int numSuccessfullySelectedCodePoints = 0;
    	while (numSuccessfullySelectedCodePoints < numCodePointsRequested) {
        	// select code point
        	final Integer             selectedCodePoint                 = new ArrayList<>(availableCodePointsAndCounts.keySet()).get(SecureRandomUtil.SECURE_RANDOM.nextInt(availableCodePointsAndCounts.size()));
    		final List<AtomicInteger> availableCodePointCountAndMax     = availableCodePointsAndCounts.get(selectedCodePoint);
    		final AtomicInteger       availableCodePointIndividualCount = availableCodePointCountAndMax.get(0);
    		final AtomicInteger       availableCodePointGroupCount      = availableCodePointCountAndMax.get(1);
    		log.info("selected  selectedCodePoint: {}, char: \"{}\", availableCodePointIndividualCount: {}, availableCodePointGroupCount: {}", selectedCodePoint, toString(selectedCodePoint), availableCodePointIndividualCount, availableCodePointGroupCount);

    		// skip if individual or group count is exhausted; remove from available code points to avoid picking it again
    		if ((availableCodePointIndividualCount.getAndDecrement() <= 0) || (availableCodePointGroupCount.getAndDecrement() <= 0)) {
	        	log.info("skipping  selectedCodePoint: {}, char: \"{}\", availableCodePointIndividualCount: {}, availableCodePointGroupCount: {}", selectedCodePoint, toString(selectedCodePoint), availableCodePointIndividualCount, availableCodePointGroupCount);
	        	System.out.print('\n');
				availableCodePointsAndCounts.remove(selectedCodePoint);
				continue;
    		}
    		selectedCodePoints.add(selectedCodePoint);
    		numSuccessfullySelectedCodePoints++;
    		log.info("remaining selectedCodePoint: {}, char: \"{}\", availableCodePointIndividualCount: {}, availableCodePointGroupCount: {}", selectedCodePoint, toString(selectedCodePoint), availableCodePointIndividualCount, availableCodePointGroupCount);
    		numUppers     = selectedCodePoints.stream().filter(c -> UPPERCASE.contains(c)).count();
    		numLowers     = selectedCodePoints.stream().filter(c -> LOWERCASE.contains(c)).count();
    		numDigits     = selectedCodePoints.stream().filter(c -> DIGITS.contains(c)).count();
    		numSpecials   = selectedCodePoints.stream().filter(c -> specials.contains(c)).count();
    		numWhitespace = selectedCodePoints.stream().filter(c -> WHITESPACE.contains(c)).count();
        	log.info("selectedCodePoints:           size: {}, uppers: {}, lowers: {}, digits: {}, specials: {}, whitespace: {}, ints: {}, chars: \"{}\"", selectedCodePoints.size(), numUppers, numLowers, numDigits, numSpecials, numWhitespace, selectedCodePoints, toString(selectedCodePoints));
        	log.info("availableCodePointsAndCounts: size: {}, ints: {}", availableCodePointsAndCounts.size(), availableCodePointsAndCounts);
        	System.out.print('\n');
        }
    }
}
