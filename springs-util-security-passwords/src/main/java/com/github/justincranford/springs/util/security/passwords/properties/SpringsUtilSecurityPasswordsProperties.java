package com.github.justincranford.springs.util.security.passwords.properties;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.PropertySource;
import org.springframework.validation.annotation.Validated;

import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;

@Configuration
@ConfigurationProperties(prefix="springs.util.security.passwords",ignoreUnknownFields=false,ignoreInvalidFields=false)
@PropertySource("classpath:springs-util-security-passwords.properties")
@Validated
@Getter
@Setter
@ToString(callSuper=false)
@Builder(toBuilder=true)
@NoArgsConstructor
@AllArgsConstructor
@SuppressWarnings({"nls"})
public class SpringsUtilSecurityPasswordsProperties {
    private Users users;
    private Clients clients;
    private Servers servers;

    public static class Users extends Properties { /*empty*/ }
    public static class Clients extends Properties { /*empty*/ }
    public static class Servers extends Properties { /*empty*/ }

    @Validated
    @Getter
    @Setter
    @ToString(callSuper = false)
    @Builder(toBuilder = true)
    @NoArgsConstructor
    @AllArgsConstructor
    public static class Properties {
        @Min(Constraints.MIN_LENGTH_MIN)
        @Max(Constraints.MIN_LENGTH_MAX)
        @Builder.Default
        private int minLength = Constraints.MIN_LENGTH_DEFAULT;

        @Min(Constraints.MAX_LENGTH_MIN)
        @Max(Constraints.MAX_LENGTH_MAX)
        @Builder.Default
        private int maxLength = Constraints.MAX_LENGTH_DEFAULT;

        @Min(Constraints.MIN_UPPERS_MIN)
        @Max(Constraints.MIN_UPPERS_MAX)
        @Builder.Default
        private int minUppers = Constraints.MIN_UPPERS_DEFAULT;

        @Min(Constraints.MAX_UPPERS_MIN)
        @Max(Constraints.MAX_UPPERS_MAX)
        @Builder.Default
        private int maxUppers = Constraints.MAX_UPPERS_DEFAULT;

        @Min(Constraints.MIN_LOWERS_MIN)
        @Max(Constraints.MIN_LOWERS_MAX)
        @Builder.Default
        private int minLowers = Constraints.MIN_LOWERS_DEFAULT;

        @Min(Constraints.MAX_LOWERS_MIN)
        @Max(Constraints.MAX_LOWERS_MAX)
        @Builder.Default
        private int maxLowers = Constraints.MAX_LOWERS_DEFAULT;

        @Min(Constraints.MIN_DIGITS_MIN)
        @Max(Constraints.MIN_DIGITS_MAX)
        @Builder.Default
        private int minDigits = Constraints.MIN_DIGITS_DEFAULT;

        @Min(Constraints.MAX_DIGITS_MIN)
        @Max(Constraints.MAX_DIGITS_MAX)
        @Builder.Default
        private int maxDigits = Constraints.MAX_DIGITS_DEFAULT;

        @Min(Constraints.MIN_SPECIALS_MIN)
        @Max(Constraints.MIN_SPECIALS_MAX)
        @Builder.Default
        private int minSpecials = Constraints.MIN_SPECIALS_DEFAULT;

        @Min(Constraints.MAX_SPECIALS_MIN)
        @Max(Constraints.MAX_SPECIALS_MAX)
        @Builder.Default
        private int maxSpecials = Constraints.MAX_SPECIALS_DEFAULT;

        @Min(Constraints.MIN_WHITESPACE_MIN)
        @Max(Constraints.MIN_WHITESPACE_MAX)
        @Builder.Default
        private int minWhitespace = Constraints.MIN_WHITESPACE_DEFAULT;

        @Min(Constraints.MAX_WHITESPACE_MIN)
        @Max(Constraints.MAX_WHITESPACE_MAX)
        @Builder.Default
        private int maxWhitespace = Constraints.MAX_WHITESPACE_DEFAULT;

        @Min(Constraints.MAX_ANYWHERE_REPEATS_MIN)
        @Max(Constraints.MAX_ANYWHERE_REPEATS_MAX)
        @Builder.Default
        private int maxAnywhereRepeats = Constraints.MAX_ANYWHERE_REPEATS_DEFAULT;

        @Min(Constraints.MAX_CONSECUTIVE_REPEATS_MIN)
        @Max(Constraints.MAX_CONSECUTIVE_REPEATS_MAX)
        @Builder.Default
        private int maxConsecutiveRepeats = Constraints.MAX_CONSECUTIVE_REPEATS_DEFAULT;

        @NotNull
        @Size(min=0)
        @Builder.Default
        private String specials = "~`!@#$%^&*()_-+={}[]|\\\"':;?/<>,.";
    }

    public static class Constraints {
        public static final int MIN_LENGTH_MIN              = 12, MIN_LENGTH_DEFAULT              =  12, MIN_LENGTH_MAX              = 128; // OWASP min 12 regular, 16 more sensitive
        public static final int MAX_LENGTH_MIN              = 43, MAX_LENGTH_DEFAULT              = 128, MAX_LENGTH_MAX              = 128; // 32-byte random => 43-char base64
        public static final int MIN_UPPERS_MIN              =  0, MIN_UPPERS_DEFAULT              =   1, MIN_UPPERS_MAX              = 128; // traditional min 1, current recommendation is min 0
        public static final int MAX_UPPERS_MIN              =  0, MAX_UPPERS_DEFAULT              = 128, MAX_UPPERS_MAX              = 128;
        public static final int MIN_LOWERS_MIN              =  0, MIN_LOWERS_DEFAULT              =   1, MIN_LOWERS_MAX              = 128; // traditional min 1, current recommendation is min 0
        public static final int MAX_LOWERS_MIN              =  0, MAX_LOWERS_DEFAULT              = 128, MAX_LOWERS_MAX              = 128;
        public static final int MIN_DIGITS_MIN              =  0, MIN_DIGITS_DEFAULT              =   1, MIN_DIGITS_MAX              = 128; // traditional min 1, current recommendation is min 0
        public static final int MAX_DIGITS_MIN              =  0, MAX_DIGITS_DEFAULT              = 128, MAX_DIGITS_MAX              = 128;
        public static final int MIN_SPECIALS_MIN            =  0, MIN_SPECIALS_DEFAULT            =   1, MIN_SPECIALS_MAX            = 128; // traditional min 1, current recommendation is min 0
        public static final int MAX_SPECIALS_MIN            =  0, MAX_SPECIALS_DEFAULT            = 128, MAX_SPECIALS_MAX            = 128;
        public static final int MIN_WHITESPACE_MIN          =  0, MIN_WHITESPACE_DEFAULT          =   0, MIN_WHITESPACE_MAX          = 128; // Allow spaces to support passphrases
        public static final int MAX_WHITESPACE_MIN          =  0, MAX_WHITESPACE_DEFAULT          =   8, MAX_WHITESPACE_MAX          = 128; // Too many may not be ideal
        public static final int MAX_ANYWHERE_REPEATS_MIN    =  0, MAX_ANYWHERE_REPEATS_DEFAULT    =   3, MAX_ANYWHERE_REPEATS_MAX    = 128;
        public static final int MAX_CONSECUTIVE_REPEATS_MIN =  0, MAX_CONSECUTIVE_REPEATS_DEFAULT =   2, MAX_CONSECUTIVE_REPEATS_MAX = 128;
    }
}
