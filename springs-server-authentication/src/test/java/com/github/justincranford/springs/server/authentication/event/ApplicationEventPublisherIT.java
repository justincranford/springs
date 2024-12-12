package com.github.justincranford.springs.server.authentication.event;

import com.github.justincranford.springs.server.authentication.AbstractIT;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.boot.actuate.audit.listener.AuditApplicationEvent;
import org.springframework.security.authentication.event.AbstractAuthenticationFailureEvent;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.session.Session;
import org.springframework.session.events.SessionCreatedEvent;

import java.util.Map;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class ApplicationEventPublisherIT extends AbstractIT {
    @Nested
    public class VerifyAuthenticationListener {
        @Test
        public void onAuthenticationSuccessEvent() {
            final AuthenticationSuccessEvent mockAuthenticationSuccessEvent = mockAuthenticationAuthenticationSuccessEventEvent();
            applicationEventPublisher().publishEvent(mockAuthenticationSuccessEvent);
            verify(authenticationListener(), times(1)).onAuthenticationSuccessEvent(mockAuthenticationSuccessEvent);
        }

        @Test
        public void onAbstractAuthenticationFailureEvent() {
            final AbstractAuthenticationFailureEvent mockAbstractAuthenticationFailureEvent = mockAbstractAuthenticationAbstractAuthenticationFailureEventEvent();
            applicationEventPublisher().publishEvent(mockAbstractAuthenticationFailureEvent);
            verify(authenticationListener(), times(1)).onAbstractAuthenticationFailureEvent(mockAbstractAuthenticationFailureEvent);
        }

        private AuthenticationSuccessEvent mockAuthenticationAuthenticationSuccessEventEvent() {
            final AuthenticationSuccessEvent mockAuthenticationSuccessEvent = mock(AuthenticationSuccessEvent.class);
            when(mockAuthenticationSuccessEvent.toString()).thenReturn("mockAuthenticationSuccessEvent");
            return mockAuthenticationSuccessEvent;
        }

        private AbstractAuthenticationFailureEvent mockAbstractAuthenticationAbstractAuthenticationFailureEventEvent() {
            final AbstractAuthenticationFailureEvent mockAbstractAuthenticationFailureEvent = mock(AbstractAuthenticationFailureEvent.class);
            when(mockAbstractAuthenticationFailureEvent.toString()).thenReturn("mockAbstractAuthenticationFailureEvent");
            return mockAbstractAuthenticationFailureEvent;
        }
    }

    @Nested
    public class VerifyLoginAttemptsLogger {
        @Test
        public void auditApplicationEvent() {
            final AuditApplicationEvent mockAuditApplicationEvent = mockAuditApplicationEvent();
            applicationEventPublisher().publishEvent(mockAuditApplicationEvent);
            verify(loginAttemptsLogger(), times(1)).auditEventHappened(mockAuditApplicationEvent);
        }

        private static AuditApplicationEvent mockAuditApplicationEvent() {
            return new AuditApplicationEvent("mockPrincipal", "LOGIN_SUCCESS", Map.of("details", new WebAuthenticationDetails("127.0.0.1", null)));
        }
    }

    @Nested
    public class VerifySessionEventListeners {
        @Test
        public void sessionCreatedEvent() {
            final SessionCreatedEvent mockSessionCreatedEvent = mockSessionCreatedEvent(mockSession());
            applicationEventPublisher().publishEvent(mockSessionCreatedEvent);
            verify(sessionEventListeners(), times(1)).sessionCreatedEvent(mockSessionCreatedEvent);
        }

        private static SessionCreatedEvent mockSessionCreatedEvent(final Session session) {
            final SessionCreatedEvent sessionCreatedEvent = mock(SessionCreatedEvent.class);
            when(sessionCreatedEvent.getSessionId()).thenReturn("mockSessionId");
            when(sessionCreatedEvent.getSource()).thenReturn("mockSource");
            when(sessionCreatedEvent.getTimestamp()).thenReturn(123L);
            when(sessionCreatedEvent.getSession()).thenReturn(session);
            return sessionCreatedEvent;
        }

        private static Session mockSession() {
            final Session mockSession = mock(Session.class);
            when(mockSession.getId()).thenReturn("1234");
            when(mockSession.toString()).thenReturn("mockSession");
            return mockSession;
        }
    }
}
