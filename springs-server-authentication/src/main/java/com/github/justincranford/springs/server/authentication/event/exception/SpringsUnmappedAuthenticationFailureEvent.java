
package com.github.justincranford.springs.server.authentication.event.exception;

import com.github.justincranford.springs.util.basic.exception.CustomAuthenticationException;
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.event.AbstractAuthenticationFailureEvent;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

import java.time.Duration;

@Slf4j
public final class SpringsUnmappedAuthenticationFailureEvent extends AbstractAuthenticationFailureEvent {
    public SpringsUnmappedAuthenticationFailureEvent(final Authentication authentication, final AuthenticationException authenticationException) {
        super(authentication, authenticationException);
        if (!(super.getException() instanceof CustomAuthenticationException)) {
            fatalUnhandledAuthenticationException(authentication, authenticationException);
        }
    }

    @SuppressFBWarnings({"DM_EXIT"})
    private static void fatalUnhandledAuthenticationException(final Authentication authentication, final AuthenticationException authenticationException) {
        final String message = "Unmapped " + authenticationException.getClass().getSimpleName() + " not expected, source: " + authentication;
        log.error(message, authenticationException);
        log.error("""
            Fatal
            
            !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
            Fatal misconfiguration of a custom AuthenticationProvider
            Custom authentication exception is missing a required interface: {}
            Shutting down JVM
            
            All custom authentication exceptions must be handled for auditing purposes
            Add missing SpringsAuthenticationException interface to {}
            
            Goodbye
            !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
            """, authenticationException.getClass().getCanonicalName(), authenticationException.getClass().getCanonicalName());
        try {
            Thread.sleep(Duration.ofMillis(50));
        } catch (InterruptedException e) {
            log.trace("Interrupted", e);
        }
        System.exit(-1);
        throw new IllegalStateException(message, authenticationException);
    }

    // toString() with override shows the exception message
    //
    // AuthenticationListener.onFailure: Client secret not matched for name [adminclient1]
    //
    //
    // toString() without override shows the authentication, not the exception
    //
    // com.github.justincranford.springs.server.authentication.event.exception.UnmappedAuthenticationFailureEvent[
    //   source=UsernamePasswordAuthenticationToken [
    //     Principal=adminclient1,
    //     Credentials=[PROTECTED],
    //     Authenticated=false,
    //     Details=WebAuthenticationDetails [
    //       RemoteIpAddress=127.0.0.1,
    //       SessionId=null
    //     ],
    //     Granted Authorities=[]
    //   ]
    // ]
    @Override
    public String toString() {
        return super.getException().getMessage();
    }
}
