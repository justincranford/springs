package com.github.justincranford.springs.util.security.passwords.constraints;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;

import com.github.justincranford.springs.util.security.passwords.properties.SpringsUtilSecurityPasswordsProperties;

@SuppressWarnings({"nls", "boxing"})
public class PasswordConstraintsUtil {
	public static PasswordConstraints proxy(final SpringsUtilSecurityPasswordsProperties.Properties properties) {
	    return (PasswordConstraints) Proxy.newProxyInstance(
	        PasswordConstraints.class.getClassLoader(),
	        new Class[]{PasswordConstraints.class},
	        new InvocationHandler() {
	            @Override
	            public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
	                switch (method.getName()) {
	                    case "minLength":             return properties.getMinLength();
	                    case "maxLength":             return properties.getMaxLength();
	                    case "maxAnywhereRepeats":    return properties.getMaxAnywhereRepeats();
	                    case "maxConsecutiveRepeats": return properties.getMaxConsecutiveRepeats();

	                    case "firsts":                return properties.getFirsts();
                        case "lasts":                 return properties.getLasts();

                        case "uppers":                return properties.getUppers();
	                    case "lowers":                return properties.getLowers();
	                    case "digits":                return properties.getDigits();
	                    case "specials":              return properties.getSpecials();
	                    case "whitespace":            return properties.getWhitespace();

	                    case "minUppers":             return properties.getMinUppers();
	                    case "maxUppers":             return properties.getMaxUppers();
	                    case "minLowers":             return properties.getMinLowers();
	                    case "maxLowers":             return properties.getMaxLowers();
	                    case "minDigits":             return properties.getMinDigits();
	                    case "maxDigits":             return properties.getMaxDigits();
	                    case "minSpecials":           return properties.getMinSpecials();
	                    case "maxSpecials":           return properties.getMaxSpecials();
	                    case "minWhitespace":         return properties.getMinWhitespace();
	                    case "maxWhitespace":         return properties.getMaxWhitespace();
	                    default:                      return method.getDefaultValue();
	                }
	            }
	        }
	    );
	}
	
}

