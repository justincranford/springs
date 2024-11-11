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
@SuppressWarnings({"nls", "boxing", "unchecked"})
public class PasswordGenerator {
	private static final AtomicInteger GENERATE_COUNT = new AtomicInteger(1);
	public static String generate(final PasswordConstraints constraints) {
		log.info("\n===================================\ngenerate test: {}", GENERATE_COUNT.getAndIncrement());
		if (constraints.maxLength() < constraints.minLength()) {
			throw new IllegalArgumentException("Max length must be greater than or equal to min");
		} else if (constraints.maxUppers() < constraints.minUppers()) {
			throw new IllegalArgumentException("Max uppers must be greater than or equal to min");
		} else if (constraints.maxLowers() < constraints.minLowers()) {
			throw new IllegalArgumentException("Max lowers must be greater than or equal to min");
		} else if (constraints.maxDigits() < constraints.minDigits()) {
			throw new IllegalArgumentException("Max digits must be greater than or equal to min");
		} else if (constraints.maxSpecials() < constraints.minSpecials()) {
			throw new IllegalArgumentException("Max specials must be greater than or equal to min");
		} else if (constraints.maxWhitespace() < constraints.minWhitespace()) {
			throw new IllegalArgumentException("Max whitespace must be greater than or equal to min");
		} else if (constraints.maxAnywhereRepeats() < 0) {
			throw new IllegalArgumentException("Max anywhere repeats must be greater than zero");
		} else if (constraints.maxConsecutiveRepeats() < 1) {
			throw new IllegalArgumentException("Max consecutive repeats must be greater than one");
		}

		final int           maxAnywhereRepeats = constraints.maxAnywhereRepeats();
		final AtomicInteger maxFirsts          = new AtomicInteger(1);                           // group count instance needs to be shared by all entries in availableFirstsCounts
		final AtomicInteger maxLasts           = new AtomicInteger(1);                           // group count instance needs to be shared by all entries in availableLastCounts
		final AtomicInteger maxUppers          = new AtomicInteger(constraints.maxUppers());     // group count instance needs to be shared by all entries in availableUppersCounts
		final AtomicInteger maxLowers          = new AtomicInteger(constraints.maxLowers());     // group count instance needs to be shared by all entries in availableLowersCounts
		final AtomicInteger maxDigits          = new AtomicInteger(constraints.maxDigits());     // group count instance needs to be shared by all entries in availableDigitsCounts
		final AtomicInteger maxSpecials        = new AtomicInteger(constraints.maxSpecials());   // group count instance needs to be shared by all entries in availableSpecialsCounts
		final AtomicInteger maxWhitespace      = new AtomicInteger(constraints.maxWhitespace()); // group count instance needs to be shared by all entries in availableWhitespaceCounts
		final List<Integer> firsts             =     constraints.firsts().codePoints().boxed().toList();
		final List<Integer> lasts              =      constraints.lasts().codePoints().boxed().toList();
		final List<Integer> uppers             =     constraints.uppers().codePoints().boxed().toList();
		final List<Integer> lowers             =     constraints.lowers().codePoints().boxed().toList();
		final List<Integer> digits             =     constraints.digits().codePoints().boxed().toList();
		final List<Integer> specials           =   constraints.specials().codePoints().boxed().toList();
		final List<Integer> whitespace         = constraints.whitespace().codePoints().boxed().toList();
		final Map<Integer, List<AtomicInteger>> availableFirstsCounts     =     firsts.stream().collect(Collectors.toMap(p -> p, p -> List.of(new AtomicInteger(maxAnywhereRepeats), maxFirsts),     (e1, e2) -> e1, LinkedHashMap::new));
		final Map<Integer, List<AtomicInteger>> availableLastsCounts      =      lasts.stream().collect(Collectors.toMap(p -> p, p -> List.of(new AtomicInteger(maxAnywhereRepeats), maxLasts),      (e1, e2) -> e1, LinkedHashMap::new));
		final Map<Integer, List<AtomicInteger>> availableUppersCounts     =     uppers.stream().collect(Collectors.toMap(p -> p, p -> List.of(new AtomicInteger(maxAnywhereRepeats), maxUppers),     (e1, e2) -> e1, LinkedHashMap::new));
		final Map<Integer, List<AtomicInteger>> availableLowersCounts     =     lowers.stream().collect(Collectors.toMap(p -> p, p -> List.of(new AtomicInteger(maxAnywhereRepeats), maxLowers),     (e1, e2) -> e1, LinkedHashMap::new));
        final Map<Integer, List<AtomicInteger>> availableDigitsCounts     =     digits.stream().collect(Collectors.toMap(p -> p, p -> List.of(new AtomicInteger(maxAnywhereRepeats), maxDigits),     (e1, e2) -> e1, LinkedHashMap::new));
        final Map<Integer, List<AtomicInteger>> availableSpecialsCounts   =   specials.stream().collect(Collectors.toMap(p -> p, p -> List.of(new AtomicInteger(maxAnywhereRepeats), maxSpecials),   (e1, e2) -> e1, LinkedHashMap::new));
        final Map<Integer, List<AtomicInteger>> availableWhitespaceCounts = whitespace.stream().collect(Collectors.toMap(p -> p, p -> List.of(new AtomicInteger(maxAnywhereRepeats), maxWhitespace), (e1, e2) -> e1, LinkedHashMap::new));

    	final int totalCodePoints = SecureRandomUtil.SECURE_RANDOM.nextInt(constraints.minLength(), constraints.maxLength() + 1);
		final List<Integer> selectedCodePoints = new ArrayList<>(totalCodePoints);
		selectCharacters(selectedCodePoints, availableFirstsCounts, 1, uppers, lowers, digits, specials, whitespace);
		selectCharacters(selectedCodePoints, availableLastsCounts,  1, uppers, lowers, digits, specials, whitespace);

		final Integer selectedFirstCodePoint = selectedCodePoints.getFirst();
		log.info("selectedFirstCodePoint: {}", selectedFirstCodePoint);
		decrementAvailable(selectedFirstCodePoint, availableUppersCounts, availableLowersCounts, availableDigitsCounts, availableSpecialsCounts, availableWhitespaceCounts);

		final Integer selectedLastCodePoint = selectedCodePoints.getLast();
		log.info("selectedLastCodePoint: {}", selectedLastCodePoint);
		decrementAvailable(selectedLastCodePoint, availableUppersCounts, availableLowersCounts, availableDigitsCounts, availableSpecialsCounts, availableWhitespaceCounts);
		System.out.println();

		selectCharacters(selectedCodePoints, availableUppersCounts,     constraints.minUppers(),     uppers, lowers, digits, specials, whitespace);
		selectCharacters(selectedCodePoints, availableLowersCounts,     constraints.minLowers(),     uppers, lowers, digits, specials, whitespace);
		selectCharacters(selectedCodePoints, availableDigitsCounts,     constraints.minDigits(),     uppers, lowers, digits, specials, whitespace);
		selectCharacters(selectedCodePoints, availableSpecialsCounts,   constraints.minSpecials(),   uppers, lowers, digits, specials, whitespace);
		selectCharacters(selectedCodePoints, availableWhitespaceCounts, constraints.minWhitespace(), uppers, lowers, digits, specials, whitespace);

    	if (selectedCodePoints.size() > constraints.maxLength()) {
            throw new IllegalArgumentException("Minimum constraints exceed maximum length; maximum length is too small");
        }

		final int remainingCodePoints = totalCodePoints - selectedCodePoints.size();
		if (remainingCodePoints > 0) {
			final Map<Integer, List<AtomicInteger>> availableCodePointsAndCounts = new LinkedHashMap<>();
	    	availableCodePointsAndCounts.putAll(availableUppersCounts);
	    	availableCodePointsAndCounts.putAll(availableLowersCounts);
	    	availableCodePointsAndCounts.putAll(availableDigitsCounts);
	    	availableCodePointsAndCounts.putAll(availableSpecialsCounts);
	    	availableCodePointsAndCounts.putAll(availableWhitespaceCounts);
			selectCharacters(selectedCodePoints, availableCodePointsAndCounts, remainingCodePoints, uppers, lowers, digits, specials, whitespace);
		}

		log.info("selectedCodePoints: {}", selectedCodePoints);
		selectedCodePoints.remove(selectedFirstCodePoint); // remove the first occurance of selected first code point
		selectedCodePoints.remove(selectedLastCodePoint);  // remove the first occurance of selected  last code point
		Collections.shuffle(selectedCodePoints);
		selectedCodePoints.addFirst(selectedFirstCodePoint); // insert the selected first code point into the first position
		selectedCodePoints.addLast(selectedLastCodePoint);   // insert the selected first code point into the  last position
    	log.info("shuffled selectedCodePoints: size: {}, uppers: {}, lowers: {}, digits: {}, specials: {}, whitespace: {}, ints: {}, chars: \"{}\"", selectedCodePoints.size(), count(selectedCodePoints, uppers), count(selectedCodePoints, lowers), count(selectedCodePoints, digits), count(selectedCodePoints, specials), count(selectedCodePoints, whitespace), selectedCodePoints, toString(selectedCodePoints));
        return toString(selectedCodePoints);
    }

    private static void selectCharacters(
		final List<Integer> selectedCodePoints,
		final Map<Integer, List<AtomicInteger>> availableCodePointsAndCounts,
		final int numCodePointsRequested,
		final List<Integer> uppers,
		final List<Integer> lowers,
		final List<Integer> digits,
		final List<Integer> specials,
		final List<Integer> whitespace
	) {
    	log.info("numCodePointsRequested: {}", numCodePointsRequested);
    	log.info("selectedCodePoints:           size: {}, uppers: {}, lowers: {}, digits: {}, specials: {}, whitespace: {}, ints: {}, chars: \"{}\"", selectedCodePoints.size(), count(selectedCodePoints, uppers), count(selectedCodePoints, lowers), count(selectedCodePoints, digits), count(selectedCodePoints, specials), count(selectedCodePoints, whitespace), selectedCodePoints, toString(selectedCodePoints));
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
        	final Integer selectedCodePoint = new ArrayList<>(availableCodePointsAndCounts.keySet()).get(SecureRandomUtil.SECURE_RANDOM.nextInt(availableCodePointsAndCounts.size()));
    		if (decrementAvailable(selectedCodePoint, availableCodePointsAndCounts)) {
        		selectedCodePoints.add(selectedCodePoint);
        		numSuccessfullySelectedCodePoints++;
            	log.info("selectedCodePoints:           size: {}, uppers: {}, lowers: {}, digits: {}, specials: {}, whitespace: {}, ints: {}, chars: \"{}\"", selectedCodePoints.size(), count(selectedCodePoints, uppers), count(selectedCodePoints, lowers), count(selectedCodePoints, digits), count(selectedCodePoints, specials), count(selectedCodePoints, whitespace), selectedCodePoints, toString(selectedCodePoints));
            	log.info("availableCodePointsAndCounts: size: {}, ints: {}", availableCodePointsAndCounts.size(), availableCodePointsAndCounts);
            	System.out.print('\n');
    		}
        }
    }

	private static boolean decrementAvailable(final Integer selectedCodePoint, final Map<Integer, List<AtomicInteger>>... availableCountsCategories) {
		for (final Map<Integer, List<AtomicInteger>> availableCountsCategory : availableCountsCategories) {
			if (availableCountsCategory.containsKey(selectedCodePoint)) {
				final List<AtomicInteger> availableCountsIndividualAndGroup = availableCountsCategory.get(selectedCodePoint);
				final AtomicInteger       availableCountIndividual          = availableCountsIndividualAndGroup.get(0);
				final AtomicInteger       availableCountGroup               = availableCountsIndividualAndGroup.get(1);
	    		log.info("selected  selectedCodePoint: {}, char: \"{}\", availableCodePointIndividualCount: {}, availableCodePointGroupCount: {}", selectedCodePoint, toString(selectedCodePoint), availableCountIndividual, availableCountGroup);
				if ((availableCountIndividual.getAndDecrement() <= 0) || (availableCountGroup.getAndDecrement() <= 0)) {
		        	log.info("skipping  selectedCodePoint: {}, char: \"{}\", availableCodePointIndividualCount: {}, availableCodePointGroupCount: {}", selectedCodePoint, toString(selectedCodePoint), availableCountIndividual, availableCountGroup);
		        	System.out.print('\n');
					availableCountsCategory.remove(selectedCodePoint);
					return false; // not enough available count to select it
				}
	    		log.info("remaining selectedCodePoint: {}, char: \"{}\", availableCodePointIndividualCount: {}, availableCodePointGroupCount: {}", selectedCodePoint, toString(selectedCodePoint), availableCountIndividual, availableCountGroup);
				return true; // select it
			}
		}
		throw new RuntimeException("Selected code point not found in any availableCounts maps");
	}

	private static long count(final List<Integer> selectedCodePoints, final List<Integer> availableCodePoints) {
		return selectedCodePoints.stream().filter(c -> availableCodePoints.contains(c)).count();
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
}
