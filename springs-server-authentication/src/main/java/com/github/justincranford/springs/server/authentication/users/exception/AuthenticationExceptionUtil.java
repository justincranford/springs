package com.github.justincranford.springs.server.authentication.users.exception;

import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.event.Level;
import org.springframework.security.core.AuthenticationException;

@NoArgsConstructor(access=AccessLevel.PRIVATE)
@Slf4j
public final class AuthenticationExceptionUtil {
	public static <EXCEPTION extends AuthenticationException> AuthenticationException logAndCreate(final Class<EXCEPTION> exceptionClass, final Level level, final String message) throws AuthenticationException {
		log.atLevel(level).setMessage(message).log();
	    try {
	        return exceptionClass.getConstructor(String.class).newInstance(message);
	    } catch (ReflectiveOperationException e) {
	        throw new RuntimeException("Failed to throw the exception of type: " + exceptionClass.getName(), e);
	    }
	}

}
