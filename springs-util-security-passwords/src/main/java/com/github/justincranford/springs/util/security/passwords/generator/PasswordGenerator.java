package com.github.justincranford.springs.util.security.passwords.generator;

import com.github.justincranford.springs.util.basic.SecureRandomUtil;
import com.github.justincranford.springs.util.security.passwords.constraints.PasswordConstraints;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;

@RequiredArgsConstructor(access = AccessLevel.PRIVATE)
@Slf4j
@SuppressWarnings({ "unchecked" })
public class PasswordGenerator {
    private final AtomicInteger generateCount = new AtomicInteger(1);
    private final PasswordConstraints constraints;

    public static PasswordGenerator create(final PasswordConstraints constraints) {
        return new PasswordGenerator(constraints);
    }

    private static void selectCharacters(
        final List<Integer> selectedCodePoints,
        final Map<Integer,List<AtomicInteger>> availableCodePointsAndCounts,
        final int numCodePointsRequested,
        final List<Integer> uppers,
        final List<Integer> lowers,
        final List<Integer> digits,
        final List<Integer> specials,
        final List<Integer> whitespace
    ) {
        log.trace("numCodePointsRequested: {}", numCodePointsRequested);
        log.trace("selectedCodePoints:           size: {}, uppers: {}, lowers: {}, digits: {}, specials: {}, whitespace: {}, ints: {}, chars: \"{}\"", selectedCodePoints.size(), count(selectedCodePoints, uppers), count(selectedCodePoints, lowers), count(selectedCodePoints, digits), count(selectedCodePoints, specials), count(selectedCodePoints, whitespace), selectedCodePoints, toString(selectedCodePoints));
        log.trace("availableCodePointsAndCounts: size: {}, ints: {}", availableCodePointsAndCounts.size(), availableCodePointsAndCounts);
        if (numCodePointsRequested <= 0) {
            log.trace("skip because no count requested, numCodePointsRequested: {}", numCodePointsRequested);
            System.out.print('\n');
            return;
        }
        final int totalIndividualCodePointsAvailable = availableCodePointsAndCounts.values().stream().map(listOfNumbers -> listOfNumbers.getFirst().intValue()).reduce(0, Integer::sum);
        if (numCodePointsRequested > totalIndividualCodePointsAvailable) {
            throw new IllegalArgumentException("Insufficient code points available " + totalIndividualCodePointsAvailable + " for request " + numCodePointsRequested + ".");
        }
        int numSuccessfullySelectedCodePoints = 0;
        while (numSuccessfullySelectedCodePoints < numCodePointsRequested) {
            final Integer selectedCodePoint = new ArrayList<>(availableCodePointsAndCounts.keySet()).get(SecureRandomUtil.SECURE_RANDOM.nextInt(availableCodePointsAndCounts.size()));
            if (decrementAvailable(selectedCodePoint, availableCodePointsAndCounts)) {
                selectedCodePoints.add(selectedCodePoint);
                numSuccessfullySelectedCodePoints++;
                log.trace("selectedCodePoints:           size: {}, uppers: {}, lowers: {}, digits: {}, specials: {}, whitespace: {}, ints: {}, chars: \"{}\"", selectedCodePoints.size(), count(selectedCodePoints, uppers), count(selectedCodePoints, lowers), count(selectedCodePoints, digits), count(selectedCodePoints, specials), count(selectedCodePoints, whitespace), selectedCodePoints, toString(selectedCodePoints));
                log.trace("availableCodePointsAndCounts: size: {}, ints: {}", availableCodePointsAndCounts.size(), availableCodePointsAndCounts);
                System.out.print('\n');
            }
        }
    }

    private static boolean decrementAvailable(final Integer selectedCodePoint, final Map<Integer,List<AtomicInteger>>... availableCountsCategories) {
        if (selectedCodePoint == null) {
            return false;
        }
        for (final Map<Integer,List<AtomicInteger>> availableCountsCategory : availableCountsCategories) {
            if (availableCountsCategory.containsKey(selectedCodePoint)) {
                final List<AtomicInteger> availableCountsIndividualAndGroup = availableCountsCategory.get(selectedCodePoint);
                final AtomicInteger availableCountIndividual = availableCountsIndividualAndGroup.get(0);
                final AtomicInteger availableCountGroup = availableCountsIndividualAndGroup.get(1);
                log.trace("selected  selectedCodePoint: {}, char: \"{}\", availableCodePointIndividualCount: {}, availableCodePointGroupCount: {}", selectedCodePoint, toString(selectedCodePoint), availableCountIndividual, availableCountGroup);
                if ((availableCountIndividual.getAndDecrement() <= 0) || (availableCountGroup.getAndDecrement() <= 0)) {
                    log.trace("skipping  selectedCodePoint: {}, char: \"{}\", availableCodePointIndividualCount: {}, availableCodePointGroupCount: {}", selectedCodePoint, toString(selectedCodePoint), availableCountIndividual, availableCountGroup);
                    System.out.print('\n');
                    availableCountsCategory.remove(selectedCodePoint);
                    return false; // not enough available count to select it
                }
                log.trace("remaining selectedCodePoint: {}, char: \"{}\", availableCodePointIndividualCount: {}, availableCodePointGroupCount: {}", selectedCodePoint, toString(selectedCodePoint), availableCountIndividual, availableCountGroup);
                return true; // select it
            }
        }
        throw new RuntimeException("Selected code point not found in any availableCounts maps");
    }

    private static long count(final List<Integer> selectedCodePoints, final List<Integer> availableCodePoints) {
        return selectedCodePoints.stream().filter(availableCodePoints::contains).count();
    }

    private static String toString(final Integer selectedCodePoint) {
        return new String(Character.toChars(selectedCodePoint));
    }

    private static String toString(final List<Integer> selectedCodePoints) {
        final StringBuilder passwordBuilder = new StringBuilder(selectedCodePoints.size());
        for (final Integer selectedCodePoint : selectedCodePoints) {
            passwordBuilder.append(Character.toChars(selectedCodePoint));
        }
        return passwordBuilder.toString();
    }

    public String generate() {
        log.trace("\n===================================\ngenerate test: {}", this.generateCount.getAndIncrement());
        if (this.constraints.maxLength() < this.constraints.minLength()) {
            throw new IllegalArgumentException("Max length must be greater than or equal to min");
        } else if (this.constraints.maxUppers() < this.constraints.minUppers()) {
            throw new IllegalArgumentException("Max uppers must be greater than or equal to min");
        } else if (this.constraints.maxLowers() < this.constraints.minLowers()) {
            throw new IllegalArgumentException("Max lowers must be greater than or equal to min");
        } else if (this.constraints.maxDigits() < this.constraints.minDigits()) {
            throw new IllegalArgumentException("Max digits must be greater than or equal to min");
        } else if (this.constraints.maxSpecials() < this.constraints.minSpecials()) {
            throw new IllegalArgumentException("Max specials must be greater than or equal to min");
        } else if (this.constraints.maxWhitespace() < this.constraints.minWhitespace()) {
            throw new IllegalArgumentException("Max whitespace must be greater than or equal to min");
        } else if (this.constraints.maxAnywhereRepeats() < 0) {
            throw new IllegalArgumentException("Max anywhere repeats must be greater than zero");
        } else if (this.constraints.maxConsecutiveRepeats() < 1) {
            throw new IllegalArgumentException("Max consecutive repeats must be greater than one");
        }

        final boolean chooseFirst = !this.constraints.firsts().isEmpty();
        final boolean chooseLast = !this.constraints.lasts().isEmpty();
        final int maxAnywhereRepeats = this.constraints.maxAnywhereRepeats();
        final AtomicInteger maxFirsts = new AtomicInteger(chooseFirst ? 1 : 0);         // group count instance needs to be shared by all entries in availableFirstsCounts
        final AtomicInteger maxLasts = new AtomicInteger(chooseLast ? 1 : 0);         // group count instance needs to be shared by all entries in availableLastCounts
        final AtomicInteger maxUppers = new AtomicInteger(this.constraints.maxUppers());     // group count instance needs to be shared by all entries in availableUppersCounts
        final AtomicInteger maxLowers = new AtomicInteger(this.constraints.maxLowers());     // group count instance needs to be shared by all entries in availableLowersCounts
        final AtomicInteger maxDigits = new AtomicInteger(this.constraints.maxDigits());     // group count instance needs to be shared by all entries in availableDigitsCounts
        final AtomicInteger maxSpecials = new AtomicInteger(this.constraints.maxSpecials());   // group count instance needs to be shared by all entries in availableSpecialsCounts
        final AtomicInteger maxWhitespace = new AtomicInteger(this.constraints.maxWhitespace()); // group count instance needs to be shared by all entries in availableWhitespaceCounts
        final List<Integer> firsts = this.constraints.firsts().codePoints().boxed().toList();
        final List<Integer> lasts = this.constraints.lasts().codePoints().boxed().toList();
        final List<Integer> uppers = this.constraints.uppers().codePoints().boxed().toList();
        final List<Integer> lowers = this.constraints.lowers().codePoints().boxed().toList();
        final List<Integer> digits = this.constraints.digits().codePoints().boxed().toList();
        final List<Integer> specials = this.constraints.specials().codePoints().boxed().toList();
        final List<Integer> whitespace = this.constraints.whitespace().codePoints().boxed().toList();
        final Map<Integer,List<AtomicInteger>> availableFirstsCounts = firsts.stream().collect(Collectors.toMap(p -> p, p -> List.of(new AtomicInteger(maxAnywhereRepeats), maxFirsts), (e1, e2) -> e1, LinkedHashMap::new));
        final Map<Integer,List<AtomicInteger>> availableLastsCounts = lasts.stream().collect(Collectors.toMap(p -> p, p -> List.of(new AtomicInteger(maxAnywhereRepeats), maxLasts), (e1, e2) -> e1, LinkedHashMap::new));
        final Map<Integer,List<AtomicInteger>> availableUppersCounts = uppers.stream().collect(Collectors.toMap(p -> p, p -> List.of(new AtomicInteger(maxAnywhereRepeats), maxUppers), (e1, e2) -> e1, LinkedHashMap::new));
        final Map<Integer,List<AtomicInteger>> availableLowersCounts = lowers.stream().collect(Collectors.toMap(p -> p, p -> List.of(new AtomicInteger(maxAnywhereRepeats), maxLowers), (e1, e2) -> e1, LinkedHashMap::new));
        final Map<Integer,List<AtomicInteger>> availableDigitsCounts = digits.stream().collect(Collectors.toMap(p -> p, p -> List.of(new AtomicInteger(maxAnywhereRepeats), maxDigits), (e1, e2) -> e1, LinkedHashMap::new));
        final Map<Integer,List<AtomicInteger>> availableSpecialsCounts = specials.stream().collect(Collectors.toMap(p -> p, p -> List.of(new AtomicInteger(maxAnywhereRepeats), maxSpecials), (e1, e2) -> e1, LinkedHashMap::new));
        final Map<Integer,List<AtomicInteger>> availableWhitespaceCounts = whitespace.stream().collect(Collectors.toMap(p -> p, p -> List.of(new AtomicInteger(maxAnywhereRepeats), maxWhitespace), (e1, e2) -> e1, LinkedHashMap::new));

        final int totalCodePoints = SecureRandomUtil.SECURE_RANDOM.nextInt(this.constraints.minLength(), this.constraints.maxLength() + 1);
        final List<Integer> selectedCodePoints = new ArrayList<>(totalCodePoints);
        selectCharacters(selectedCodePoints, availableFirstsCounts, chooseFirst ? 1 : 0, uppers, lowers, digits, specials, whitespace);
        selectCharacters(selectedCodePoints, availableLastsCounts, chooseLast ? 1 : 0, uppers, lowers, digits, specials, whitespace);

        final Integer selectedFirstCodePoint = (chooseFirst) ? selectedCodePoints.getFirst() : null;
        log.trace("selectedFirstCodePoint: {}", selectedFirstCodePoint);
        decrementAvailable(selectedFirstCodePoint, availableUppersCounts, availableLowersCounts, availableDigitsCounts, availableSpecialsCounts, availableWhitespaceCounts);

        final Integer selectedLastCodePoint = (chooseLast) ? selectedCodePoints.getLast() : null;
        log.trace("selectedLastCodePoint: {}", selectedLastCodePoint);
        decrementAvailable(selectedLastCodePoint, availableUppersCounts, availableLowersCounts, availableDigitsCounts, availableSpecialsCounts, availableWhitespaceCounts);
        System.out.println();

        selectCharacters(selectedCodePoints, availableUppersCounts, this.constraints.minUppers(), uppers, lowers, digits, specials, whitespace);
        selectCharacters(selectedCodePoints, availableLowersCounts, this.constraints.minLowers(), uppers, lowers, digits, specials, whitespace);
        selectCharacters(selectedCodePoints, availableDigitsCounts, this.constraints.minDigits(), uppers, lowers, digits, specials, whitespace);
        selectCharacters(selectedCodePoints, availableSpecialsCounts, this.constraints.minSpecials(), uppers, lowers, digits, specials, whitespace);
        selectCharacters(selectedCodePoints, availableWhitespaceCounts, this.constraints.minWhitespace(), uppers, lowers, digits, specials, whitespace);

        if (selectedCodePoints.size() > this.constraints.maxLength()) {
            throw new IllegalArgumentException("Minimum constraints exceed maximum length; maximum length is too small");
        }

        final int remainingCodePoints = totalCodePoints - selectedCodePoints.size();
        if (remainingCodePoints > 0) {
            final Map<Integer,List<AtomicInteger>> availableCodePointsAndCounts = new LinkedHashMap<>();
            availableCodePointsAndCounts.putAll(availableUppersCounts);
            availableCodePointsAndCounts.putAll(availableLowersCounts);
            availableCodePointsAndCounts.putAll(availableDigitsCounts);
            availableCodePointsAndCounts.putAll(availableSpecialsCounts);
            availableCodePointsAndCounts.putAll(availableWhitespaceCounts);
            selectCharacters(selectedCodePoints, availableCodePointsAndCounts, remainingCodePoints, uppers, lowers, digits, specials, whitespace);
        }

        log.trace("selectedCodePoints: {}", selectedCodePoints);
        if (chooseFirst) {
            final boolean foundFirst = selectedCodePoints.remove(selectedFirstCodePoint);   // remove the first occurance of selected first code point
            assert foundFirst : "Selected first code point not found";
        }
        if (chooseLast) {
            final boolean foundLast = selectedCodePoints.remove(selectedLastCodePoint);    // remove the first occurance of selected last code point
            assert foundLast : "Selected last code point not found";
        }
        Collections.shuffle(selectedCodePoints);
        if (chooseFirst) {
            selectedCodePoints.addFirst(selectedFirstCodePoint); // insert the selected first code point into the first position
        }
        if (chooseLast) {
            selectedCodePoints.addLast(selectedLastCodePoint);   // insert the selected last code point into the last position
        }
        log.trace("final selectedCodePoints: size: {}, uppers: {}, lowers: {}, digits: {}, specials: {}, whitespace: {}, ints: {}, chars: \"{}\"", selectedCodePoints.size(), count(selectedCodePoints, uppers), count(selectedCodePoints, lowers), count(selectedCodePoints, digits), count(selectedCodePoints, specials), count(selectedCodePoints, whitespace), selectedCodePoints, toString(selectedCodePoints));
        return toString(selectedCodePoints);
    }
}
