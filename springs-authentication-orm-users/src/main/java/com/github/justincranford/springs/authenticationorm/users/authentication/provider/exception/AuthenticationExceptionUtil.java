package com.github.justincranford.springs.authenticationorm.users.authentication.provider.exception;

import org.slf4j.event.Level;
import org.springframework.security.core.AuthenticationException;

import lombok.extern.slf4j.Slf4j;

@Slf4j
public class AuthenticationExceptionUtil {
	public static <EXCEPTION extends AuthenticationException> AuthenticationException logAndCreate(final Class<EXCEPTION> exceptionClass, final Level level, final String message) throws AuthenticationException {
		log.atLevel(level).setMessage(message).log();
	    try {
	        return exceptionClass.getConstructor(String.class).newInstance(message);
	    } catch (ReflectiveOperationException e) {
	        throw new RuntimeException("Failed to throw the exception of type: " + exceptionClass.getName(), e);
	    }
	}
	
}

