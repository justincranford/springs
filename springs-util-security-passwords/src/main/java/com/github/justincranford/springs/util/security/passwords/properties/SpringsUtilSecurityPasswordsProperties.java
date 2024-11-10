package com.github.justincranford.springs.util.security.passwords.properties;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.PropertySource;
import org.springframework.validation.annotation.Validated;

import com.github.justincranford.springs.util.security.passwords.constraints.PasswordConstraintsValues;

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
        @NotNull
        @Size(min=0)
        @Builder.Default
        private String firsts = PasswordConstraintsValues.FIRSTS_DEFAULT;

        @NotNull
        @Size(min=0)
        @Builder.Default
        private String uppers = PasswordConstraintsValues.UPPERS_DEFAULT;

        @NotNull
        @Size(min=0)
        @Builder.Default
        private String lowers = PasswordConstraintsValues.LOWERS_DEFAULT;

        @NotNull
        @Size(min=0)
        @Builder.Default
        private String digits = PasswordConstraintsValues.DIGITS_DEFAULT;

        @NotNull
        @Size(min=0)
        @Builder.Default
        private String specials = PasswordConstraintsValues.SPECIALS_DEFAULT;

        @NotNull
        @Size(min=0)
        @Builder.Default
        private String whitespace = PasswordConstraintsValues.WHITESPACE_DEFAULT;

        @Min(PasswordConstraintsValues.MIN_LENGTH_MIN)
        @Max(PasswordConstraintsValues.MIN_LENGTH_MAX)
        @Builder.Default
        private int minLength = PasswordConstraintsValues.MIN_LENGTH_DEFAULT;

        @Min(PasswordConstraintsValues.MAX_LENGTH_MIN)
        @Max(PasswordConstraintsValues.MAX_LENGTH_MAX)
        @Builder.Default
        private int maxLength = PasswordConstraintsValues.MAX_LENGTH_DEFAULT;

        @Min(PasswordConstraintsValues.MIN_UPPERS_MIN)
        @Max(PasswordConstraintsValues.MIN_UPPERS_MAX)
        @Builder.Default
        private int minUppers = PasswordConstraintsValues.MIN_UPPERS_DEFAULT;

        @Min(PasswordConstraintsValues.MAX_UPPERS_MIN)
        @Max(PasswordConstraintsValues.MAX_UPPERS_MAX)
        @Builder.Default
        private int maxUppers = PasswordConstraintsValues.MAX_UPPERS_DEFAULT;

        @Min(PasswordConstraintsValues.MIN_LOWERS_MIN)
        @Max(PasswordConstraintsValues.MIN_LOWERS_MAX)
        @Builder.Default
        private int minLowers = PasswordConstraintsValues.MIN_LOWERS_DEFAULT;

        @Min(PasswordConstraintsValues.MAX_LOWERS_MIN)
        @Max(PasswordConstraintsValues.MAX_LOWERS_MAX)
        @Builder.Default
        private int maxLowers = PasswordConstraintsValues.MAX_LOWERS_DEFAULT;

        @Min(PasswordConstraintsValues.MIN_DIGITS_MIN)
        @Max(PasswordConstraintsValues.MIN_DIGITS_MAX)
        @Builder.Default
        private int minDigits = PasswordConstraintsValues.MIN_DIGITS_DEFAULT;

        @Min(PasswordConstraintsValues.MAX_DIGITS_MIN)
        @Max(PasswordConstraintsValues.MAX_DIGITS_MAX)
        @Builder.Default
        private int maxDigits = PasswordConstraintsValues.MAX_DIGITS_DEFAULT;

        @Min(PasswordConstraintsValues.MIN_SPECIALS_MIN)
        @Max(PasswordConstraintsValues.MIN_SPECIALS_MAX)
        @Builder.Default
        private int minSpecials = PasswordConstraintsValues.MIN_SPECIALS_DEFAULT;

        @Min(PasswordConstraintsValues.MAX_SPECIALS_MIN)
        @Max(PasswordConstraintsValues.MAX_SPECIALS_MAX)
        @Builder.Default
        private int maxSpecials = PasswordConstraintsValues.MAX_SPECIALS_DEFAULT;

        @Min(PasswordConstraintsValues.MIN_WHITESPACE_MIN)
        @Max(PasswordConstraintsValues.MIN_WHITESPACE_MAX)
        @Builder.Default
        private int minWhitespace = PasswordConstraintsValues.MIN_WHITESPACE_DEFAULT;

        @Min(PasswordConstraintsValues.MAX_WHITESPACE_MIN)
        @Max(PasswordConstraintsValues.MAX_WHITESPACE_MAX)
        @Builder.Default
        private int maxWhitespace = PasswordConstraintsValues.MAX_WHITESPACE_DEFAULT;

        @Min(PasswordConstraintsValues.MAX_ANYWHERE_REPEATS_MIN)
        @Max(PasswordConstraintsValues.MAX_ANYWHERE_REPEATS_MAX)
        @Builder.Default
        private int maxAnywhereRepeats = PasswordConstraintsValues.MAX_ANYWHERE_REPEATS_DEFAULT;

        @Min(PasswordConstraintsValues.MAX_CONSECUTIVE_REPEATS_MIN)
        @Max(PasswordConstraintsValues.MAX_CONSECUTIVE_REPEATS_MAX)
        @Builder.Default
        private int maxConsecutiveRepeats = PasswordConstraintsValues.MAX_CONSECUTIVE_REPEATS_DEFAULT;
    }
}
