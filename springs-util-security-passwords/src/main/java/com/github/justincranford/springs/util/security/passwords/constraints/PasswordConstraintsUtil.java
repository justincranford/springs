package com.github.justincranford.springs.util.security.passwords.constraints;

import com.github.justincranford.springs.util.security.passwords.properties.SpringsUtilSecurityPasswordsProperties;

import java.lang.reflect.Proxy;

public class PasswordConstraintsUtil {
    public static PasswordConstraints proxy(final SpringsUtilSecurityPasswordsProperties.Properties properties) {
        return (PasswordConstraints) Proxy.newProxyInstance(
            PasswordConstraints.class.getClassLoader(),
            new Class[] { PasswordConstraints.class },
            (proxy, method, args) -> switch (method.getName()) {
                case "minLength" -> properties.getMinLength();
                case "maxLength" -> properties.getMaxLength();
                case "maxAnywhereRepeats" -> properties.getMaxAnywhereRepeats();
                case "maxConsecutiveRepeats" -> properties.getMaxConsecutiveRepeats();
                case "firsts" -> properties.getFirsts();
                case "lasts" -> properties.getLasts();
                case "uppers" -> properties.getUppers();
                case "lowers" -> properties.getLowers();
                case "digits" -> properties.getDigits();
                case "specials" -> properties.getSpecials();
                case "whitespace" -> properties.getWhitespace();
                case "minUppers" -> properties.getMinUppers();
                case "maxUppers" -> properties.getMaxUppers();
                case "minLowers" -> properties.getMinLowers();
                case "maxLowers" -> properties.getMaxLowers();
                case "minDigits" -> properties.getMinDigits();
                case "maxDigits" -> properties.getMaxDigits();
                case "minSpecials" -> properties.getMinSpecials();
                case "maxSpecials" -> properties.getMaxSpecials();
                case "minWhitespace" -> properties.getMinWhitespace();
                case "maxWhitespace" -> properties.getMaxWhitespace();
                default -> throw new RuntimeException("Method " + method.getName() + " + proxy is missing");
            }
        );
    }
}
