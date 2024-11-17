package com.github.justincranford.springs.util.basic;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Example of static methods to start/stop timers.
 * <p>
 * Timer.setLogTimeUnit(TimeUnit.MICROSECONDS);
 * Timer.start("timer1");
 * // do something, "timer1" will accumulate time for it
 * Timer.start("timer2");
 * // do something, "timer1" and "timer2" accumulate time for it
 * Timer.stop("timer1");	// Triggers print "timer1" details (if currentAutoPrintInternal matches)
 * // do something, "timer2" will accumulate time for it
 * Timer.start("timer3");
 * // do something, "timer2" and "timer3" will accumulate time for it
 * Timer.stop("timer3");	// Triggers print "timer3" details (if currentAutoPrintInternal matches)
 * // do something, "timer2" will accumulate time for it
 * Timer.stop("timer2");	// Triggers print "timer2" details (if currentAutoPrintInternal matches)
 * <p>
 * Example of objects to start/stop timers.
 * <p>
 * Timer.setLogTimeUnit(TimeUnit.MICROSECONDS);
 * Timer timer1 = new Timer("timer1");
 * // do something, "timer1" will accumulate time for it
 * timer1.close();
 * <p>
 * Example of objects to start/stop timers via auto-close (Java 7+).
 * <p>
 * Timer.setLogTimeUnit(TimeUnit.SECONDS);
 * try (Timer timer2 = new Timer("timer2")) {
 * // do something, "timer2" will accumulate time for it
 * try (Timer timer3 = new Timer("timer3")) {
 * // do something, "timer2" and "timer3" will accumulate time for it
 * } // Triggers print "timer3" details (if currentAutoPrintInternal matches)
 * } // Triggers print "timer2" details (if currentAutoPrintInternal matches)
 */
public class Timer implements AutoCloseable {
    private static final Logger LOG = Logger.getLogger(Timer.class.getCanonicalName());

    private static final Long LONG_ZERO = Long.valueOf(0);

    private static final Map<String,Long> TOTAL_NANO_TIMES = new LinkedHashMap<>();    // insertion ordered by start(String)
    private static final Map<String,Long> TOTAL_ITERATIONS = new LinkedHashMap<>();    // insertion ordered by start(String)
    private static final Set<String> STOPPED_TIMERS = new LinkedHashSet<>();    // insertion ordered by stop(String)

    private static final Level DEFAULT_LOG_LEVEL = Level.INFO;
    private static final TimeUnit DEFAULT_LOG_TOTAL_TIME_UNIT = TimeUnit.SECONDS;
    private static final TimeUnit DEFAULT_LOG_AVERAGE_TIME_UNIT = TimeUnit.MILLISECONDS;
    private static final int DEFAULT_AUTO_LOG_INTERNAL = 1;
    private static final int DEFAULT_AUTO_RESET_INTERVAL = 0;

    private static Level currentLogLevel = Timer.DEFAULT_LOG_LEVEL;
    private static TimeUnit currentLogTotalTimeUnit = Timer.DEFAULT_LOG_TOTAL_TIME_UNIT;
    private static TimeUnit currentLogAverageTimeUnit = Timer.DEFAULT_LOG_AVERAGE_TIME_UNIT;
    private static int currentAutoLogInternal = Timer.DEFAULT_AUTO_LOG_INTERNAL;
    private static int currentAutoResetInterval = Timer.DEFAULT_AUTO_RESET_INTERVAL;

    private String[] reverseTimers;

    public Timer(final String... timers) {
        Timer.start(timers);
        final List<String> asList = Arrays.asList(timers);
        Collections.reverse(asList);
        this.reverseTimers = asList.toArray(new String[timers.length]);
    }

    // Substract current nanoTime at start. Adding future nanoTime at stop yields an overall positive increment for the internal.
    public static synchronized void start(final String... timers) {
        for (final String timer : timers) {
            final Long oldTotalTime = Timer.TOTAL_NANO_TIMES.get(timer);
            if (null == oldTotalTime) {
                Timer.TOTAL_NANO_TIMES.put(timer, Long.valueOf(LONG_ZERO.longValue() - System.nanoTime()));
                Timer.TOTAL_ITERATIONS.put(timer, LONG_ZERO);
            } else {
                Timer.TOTAL_NANO_TIMES.put(timer, Long.valueOf(oldTotalTime.longValue() - System.nanoTime()));
                // Iterations will be incremented at stop.
            }
        }
    }

    public static Timer go(final String... timers) {
        return new Timer(timers);
    }

    public static synchronized void setLogLevel(final Level newLogLevel) {
        Timer.currentLogLevel = newLogLevel;
    }

    public static synchronized void setLogTotalTimeUnit(final TimeUnit newLogTotalTimeUnit) {
        Timer.currentLogTotalTimeUnit = newLogTotalTimeUnit;
    }

    public static synchronized void setLogAverageTimeUnit(final TimeUnit newLogAverageTimeUnit) {
        Timer.currentLogAverageTimeUnit = newLogAverageTimeUnit;
    }

    public static synchronized void setAutoLogInterval(int newAutoPrintInterval) {
        Timer.currentAutoLogInternal = newAutoPrintInterval;
    }

    public static synchronized void setAutoResetInterval(int newResetInterval) {
        Timer.currentAutoResetInterval = newResetInterval;
    }

    public static synchronized void reset() {
        Timer.resetLogLevel();
        Timer.resetLogTotalTimeUnit();
        Timer.resetLogAverageTimeUnit();
        Timer.resetAutoLogInterval();
        Timer.resetAutoResetInterval();
        Timer.resetTimers();
    }

    public static synchronized void resetLogLevel() {
        Timer.currentLogLevel = Timer.DEFAULT_LOG_LEVEL;
    }

    public static synchronized void resetLogTotalTimeUnit() {
        Timer.currentLogTotalTimeUnit = Timer.DEFAULT_LOG_TOTAL_TIME_UNIT;
    }

    public static synchronized void resetLogAverageTimeUnit() {
        Timer.currentLogAverageTimeUnit = Timer.DEFAULT_LOG_AVERAGE_TIME_UNIT;
    }

    public static synchronized void resetAutoLogInterval() {
        Timer.currentAutoLogInternal = Timer.DEFAULT_AUTO_LOG_INTERNAL;
    }

    public static synchronized void resetAutoResetInterval() {
        Timer.currentAutoResetInterval = Timer.DEFAULT_AUTO_RESET_INTERVAL;
    }

    public static synchronized void resetTimers() {
        Timer.TOTAL_NANO_TIMES.clear();
        Timer.TOTAL_ITERATIONS.clear();
        Timer.STOPPED_TIMERS.clear();
    }

    public static synchronized void startStop(final String timer) {
        Timer.start(timer);
        Timer.stop(timer);
    }

    public static synchronized void stop(final String... timers) {
        for (final String timer : timers) {
            final Long oldTotalTime = Timer.TOTAL_NANO_TIMES.get(timer);
            final Long oldIterations = Timer.TOTAL_ITERATIONS.get(timer);
            if ((null == oldTotalTime) || (null == oldIterations)) {
                return;
            }
            final long newTotalTime = oldTotalTime.longValue() + System.nanoTime();
            final long newIterations = oldIterations.longValue() + 1;

            if ((0 != currentAutoResetInterval) && (newIterations == currentAutoResetInterval)) {
                Timer.resetTimer(timer);
            } else {
                Timer.TOTAL_NANO_TIMES.put(timer, Long.valueOf(newTotalTime));
                Timer.TOTAL_ITERATIONS.put(timer, Long.valueOf(newIterations));
                Timer.STOPPED_TIMERS.add(timer);
            }

            if ((0 != currentAutoLogInternal) && (0 == (newIterations % currentAutoLogInternal))) {
                LOG.log(Timer.currentLogLevel, Timer.appendTimer(new StringBuilder(), timer, Long.valueOf(newTotalTime), Long.valueOf(newIterations)).toString());
            }
        }
    }

    public static synchronized void resetTimer(final String timer) {
        Timer.TOTAL_NANO_TIMES.remove(timer);
        Timer.TOTAL_ITERATIONS.remove(timer);
        Timer.STOPPED_TIMERS.remove(timer);
    }

    @SuppressWarnings("cast")
    /*package*/ static StringBuilder appendTimer(final StringBuilder sb, final String timer, final Long time, final Long iterations) {
        final float floatTime = (float) time.longValue();
        final float totalTimeFloat = Timer.normalizeNanoTimeToTimeUnits(floatTime, Timer.currentLogTotalTimeUnit);
        final float averageTimeFloat = Timer.normalizeNanoTimeToTimeUnits(floatTime / iterations.longValue(), Timer.currentLogAverageTimeUnit);
        final String totalTimeUnit = Timer.convertTimeUnitsToStringAbbreviation(Timer.currentLogTotalTimeUnit);
        final String averageTimeUnit = Timer.convertTimeUnitsToStringAbbreviation(Timer.currentLogAverageTimeUnit);
        return sb.append("Timer[").append(timer).append("] Iterations=").append(iterations).append(", Avg=").append(averageTimeFloat).append(" ").append(averageTimeUnit).append(", Total=").append(totalTimeFloat).append(" ").append(totalTimeUnit);
    }

    private static float normalizeNanoTimeToTimeUnits(final float nanoTime, final TimeUnit timeUnit) {    // NOSONAR The Cyclomatic Complexity of this method "convertTimeToTimeUnits" is 11 which is greater than 10 authorized.
        switch (timeUnit) {
            case NANOSECONDS:
                return nanoTime;
            case MICROSECONDS:
                return nanoTime / 1000F;
            case MILLISECONDS:
                return nanoTime / 1000000F;
            case SECONDS:
                return nanoTime / 1000000000F;
            case MINUTES:
                return nanoTime / 60000000000F;
            case HOURS:
                return nanoTime / 3600000000000F;
            case DAYS:
                return nanoTime / 86400000000000F;
            default:
                return Float.MIN_VALUE;
        }
    }

    /*package*/
    static String convertTimeUnitsToStringAbbreviation(final TimeUnit timeUnit) {
        if (null == timeUnit) {
            return null;
        }
        switch (timeUnit) {
            case NANOSECONDS:
                return "nsec";
            case MICROSECONDS:
                return "usec";
            case MILLISECONDS:
                return "msec";
            case SECONDS:
                return "sec";
            case MINUTES:
                return "min";
            case HOURS:
                return "hour";
            case DAYS:
                return "day";
            default:
                return null;
        }
    }

    public static synchronized float getTotalTime(final String timer) {
        return Timer.getTotalTime(timer, Timer.currentLogTotalTimeUnit);
    }

    public static synchronized float getTotalTime(final String timer, final TimeUnit timeUnit) {
        return Timer.normalizeNanoTimeToTimeUnits(Timer.TOTAL_NANO_TIMES.get(timer), timeUnit);
    }

    /*package*/
    static float normalizeNanoTimeToTimeUnits(final Long nanoTime, final TimeUnit timeUnit) {    // NOSONAR The Cyclomatic Complexity of this method "convertTimeToTimeUnits" is 11 which is greater than 10 authorized.
        return (null == nanoTime) ? Float.MIN_VALUE : Timer.normalizeNanoTimeToTimeUnits(nanoTime.longValue(), timeUnit);
    }

    public static synchronized float getAverageTime(final String timer) {
        return Timer.getAverageTime(timer, Timer.currentLogAverageTimeUnit);
    }

    public static synchronized float getAverageTime(final String timer, final TimeUnit timeUnit) {
        final Long currentIterationsObj = Timer.getIterations(timer);
        final float currentTotalTime = Timer.normalizeNanoTimeToTimeUnits(Timer.TOTAL_NANO_TIMES.get(timer), timeUnit);
        if ((null == currentIterationsObj) || (0 == currentIterationsObj.longValue())) {
            return Float.MIN_VALUE;
        }
        return currentTotalTime / currentIterationsObj.longValue();
    }

    public static synchronized Long getIterations(final String timer) {
        return Timer.TOTAL_ITERATIONS.get(timer);
    }

    public static synchronized void logAllOrderedByStartTime(final boolean isAscending) {
        Timer.logAllHelper(new ArrayList<>(Timer.TOTAL_NANO_TIMES.keySet()), "All timers, ordered by start time", isAscending);    // Insertion order = Start time asc order
    }

    /*package*/
    static void logAllHelper(final List<String> timerSet, final String message, final boolean isAscending) {
        if (!isAscending) {
            Collections.reverse(timerSet);
        }
        final StringBuilder sb = new StringBuilder(message).append(isAscending ? " ascending" : " descending").append("\n");
        for (final String timer : timerSet) {
            final Long currentTotalTime = Timer.TOTAL_NANO_TIMES.get(timer);
            final Long currentIterations = Timer.TOTAL_ITERATIONS.get(timer);
            if ((null == currentTotalTime) || (null == currentIterations)) {
                continue;
            }
            Timer.appendTimer(sb, timer, currentTotalTime, currentIterations).append("\n");
        }
        LOG.log(Timer.currentLogLevel, sb.toString());
    }

    public static synchronized void logAllOrderedByStopTime(final boolean isAscending) {
        Timer.logAllHelper(new ArrayList<>(Timer.STOPPED_TIMERS), "All timers, ordered by stop time", isAscending);    // Stopped order
    }

    public static synchronized void logAllOrderedByName(final boolean isAscending) {
        Timer.logAllHelper(new ArrayList<>(new TreeSet<>(Timer.TOTAL_NANO_TIMES.keySet())), "All timers, ordered by name", isAscending);    // Name asc order
    }

    public static synchronized void logAllOrderedByTotalTime(final boolean isAscending) {
        final TreeMap<Long,List<String>> orderedTotalTimes = new TreeMap<>();    // ordered by keys
        for (final Entry<String,Long> entry : Timer.TOTAL_NANO_TIMES.entrySet()) {
            final String timer = entry.getKey();
            final Long totalTime = entry.getValue();
            List<String> timers = orderedTotalTimes.get(totalTime);
            if (null == timers) {
                timers = new ArrayList<>();
            }
            timers.add(timer);
            orderedTotalTimes.put(totalTime, timers);
        }
        final List<String> timersOrderedByTotalTime = new ArrayList<>();
        for (final Entry<Long,List<String>> entry : orderedTotalTimes.entrySet()) {
            timersOrderedByTotalTime.addAll(entry.getValue());    // add all timer names for current total time
        }
        Timer.logAllHelper(timersOrderedByTotalTime, "All timers, ordered by total time", isAscending);
    }

    public static synchronized void logAllOrderedByAverageTime(final boolean isAscending) {
        final TreeMap<Float,List<String>> orderedAverageTimes = new TreeMap<>();    // ordered by keys
        for (final Entry<String,Long> entry : Timer.TOTAL_NANO_TIMES.entrySet()) {
            final String timer = entry.getKey();
            final Long totalTime = entry.getValue();
            final Long iterations = Timer.TOTAL_ITERATIONS.get(timer);
            final Float averageTime;
            if ((null == iterations) || (0L == iterations.longValue())) {
                averageTime = Float.valueOf(Float.MIN_VALUE);
            } else {
                averageTime = Float.valueOf(((float) totalTime.longValue()) / iterations.longValue());
            }
            List<String> timers = orderedAverageTimes.get(averageTime);
            if (null == timers) {
                timers = new ArrayList<>();
            }
            timers.add(timer);
            orderedAverageTimes.put(averageTime, timers);
        }
        final List<String> timersOrderedByTotalTime = new ArrayList<>();
        for (final Entry<Float,List<String>> entry : orderedAverageTimes.entrySet()) {
            timersOrderedByTotalTime.addAll(entry.getValue());    // add all timer names for current average time
        }
        Timer.logAllHelper(timersOrderedByTotalTime, "All timers, ordered by average time", isAscending);
    }

    @Override
    public void close() {
        Timer.stop(this.reverseTimers);
    }
}
