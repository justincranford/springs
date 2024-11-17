package com.github.justincranford.springs.util.basic;

import java.time.Clock;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;

@SuppressWarnings({"unused"})
public class DateTimeUtil {
    public static final Clock CLOCK_SYSTEM_UTC = Clock.systemUTC();

    public static OffsetDateTime nowUtcTruncatedToDays() {
        return OffsetDateTime.now(CLOCK_SYSTEM_UTC).truncatedTo(ChronoUnit.DAYS);
    }

    public static OffsetDateTime nowUtcTruncatedToHours() {
        return OffsetDateTime.now(CLOCK_SYSTEM_UTC).truncatedTo(ChronoUnit.HOURS);
    }

    public static OffsetDateTime nowUtcTruncatedToMinutes() {
        return OffsetDateTime.now(CLOCK_SYSTEM_UTC).truncatedTo(ChronoUnit.MINUTES);
    }

    public static OffsetDateTime nowUtcTruncatedToSeconds() {
        return OffsetDateTime.now(CLOCK_SYSTEM_UTC).truncatedTo(ChronoUnit.SECONDS);
    }

    public static OffsetDateTime nowUtcTruncatedToMilliseconds() {
        return OffsetDateTime.now(CLOCK_SYSTEM_UTC).truncatedTo(ChronoUnit.MILLIS);
    }

    public static OffsetDateTime nowUtcTruncatedToMicroseconds() {
        return OffsetDateTime.now(CLOCK_SYSTEM_UTC).truncatedTo(ChronoUnit.MICROS);
    }

    public static OffsetDateTime nowUtcTruncatedToNanoseconds() {
        return OffsetDateTime.now(CLOCK_SYSTEM_UTC).truncatedTo(ChronoUnit.NANOS);
    }

    public static OffsetDateTime toOffsetDateTime(final long epochMillis) {
        return OffsetDateTime.ofInstant(Instant.ofEpochMilli(epochMillis), ZoneOffset.UTC);
    }
}
