package com.github.justincranford.springs.server.authentication.event.listener;

import lombok.extern.slf4j.Slf4j;
import org.jetbrains.annotations.NotNull;
import org.springframework.context.event.EventListener;
import org.springframework.security.core.session.SessionIdChangedEvent;
import org.springframework.session.events.SessionCreatedEvent;
import org.springframework.session.events.SessionDeletedEvent;
import org.springframework.session.events.SessionDestroyedEvent;
import org.springframework.session.events.SessionExpiredEvent;
import org.springframework.stereotype.Component;

@Component
@Slf4j
public class SessionEventListeners {
    @EventListener
    public void sessionCreatedEvent(final @NotNull SessionCreatedEvent e) {
        log.info("SessionEventListener.{}, ID: {}, Timestamp: {}, Source: {}, Event: {}", e.getClass().getSimpleName(), e.getSessionId(), e.getTimestamp(), e.getSource(), e);
    }

    private static void extracted(final @NotNull SessionIdChangedEvent e) {
        log.info("SessionEventListener.{}, New ID: {}, Old ID: {}, Timestamp: {}, Source: {}, Event: {}", e.getClass().getSimpleName(), e.getNewSessionId(), e.getOldSessionId(), e.getTimestamp(), e.getSource(), e);
    }

    @EventListener
    public void sessionExpiredEvent(final @NotNull SessionExpiredEvent e) {
        log.info("SessionEventListener.{}, ID: {}, Timestamp: {}, Source: {}, Event: {}", e.getClass().getSimpleName(), e.getSessionId(), e.getTimestamp(), e.getSource(), e);
    }

    @EventListener
    public void sessionDestroyedEvent(final @NotNull SessionDestroyedEvent e) {
        log.info("SessionEventListener.{}, ID: {}, Timestamp: {}, Source: {}, Event: {}", e.getClass().getSimpleName(), e.getSessionId(), e.getTimestamp(), e.getSource(), e);
    }

    @EventListener
    public void sessionDeletedEvent(final @NotNull SessionDeletedEvent e) {
        log.info("SessionEventListener.{}, ID: {}, Timestamp: {}, Source: {}, Event: {}", e.getClass().getSimpleName(), e.getSessionId(), e.getTimestamp(), e.getSource(), e);
    }
}
