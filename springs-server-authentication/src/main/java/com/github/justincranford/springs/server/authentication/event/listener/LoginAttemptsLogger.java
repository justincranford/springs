package com.github.justincranford.springs.server.authentication.event.listener;

import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.actuate.audit.AuditEvent;
import org.springframework.boot.actuate.audit.listener.AuditApplicationEvent;
import org.springframework.context.event.EventListener;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.stereotype.Component;

@Component
@Slf4j
public class LoginAttemptsLogger {
    @EventListener
    public void auditEventHappened(final AuditApplicationEvent auditApplicationEvent) {
        final AuditEvent auditEvent = auditApplicationEvent.getAuditEvent();
        log.info("LoginAttemptsLogger.auditEventHappened Principal {} - {}", auditEvent.getPrincipal(), auditEvent.getType());
        final WebAuthenticationDetails details = (WebAuthenticationDetails) auditEvent.getData().get("details");
        log.info("LoginAttemptsLogger.auditEventHappened Remote IP address: {}", details.getRemoteAddress());
        log.info("LoginAttemptsLogger.auditEventHappened Session Id: {}", details.getSessionId());
    }
}
