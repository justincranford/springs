package com.github.justincranford.springs.persistenceredis.sessions.listener;

import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
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
    @PostConstruct
    public void postConstruct() {
        log.info("SessionEventListener.postConstruct");
    }

    @PreDestroy
    public void preDestroy() {
        log.info("SessionEventListener.preDestroy");
    }

    @EventListener
    public void sessionCreatedEvent(final @NotNull SessionCreatedEvent e) {
        log.info("SessionEventListener.sessionCreatedEvent, Event: {}, ID: {}, Timestamp: {}, Source: {}", e.getClass().getSimpleName(), e.getSessionId(), e.getTimestamp(), e.getSource());
    }

    @EventListener
    public void sessionIdChangedEvent(final @NotNull SessionIdChangedEvent e) {
        log.info("SessionEventListener.sessionIdChangedEvent, Event: {}, New ID: {}, Old ID: {}, Timestamp: {}, Source: {}", e.getClass().getSimpleName(), e.getNewSessionId(), e.getOldSessionId(), e.getTimestamp(), e.getSource());
    }

    @EventListener
    public void sessionExpiredEvent(final @NotNull SessionExpiredEvent e) {
        log.info("SessionEventListener.sessionExpiredEvent, Event: {}, ID: {}, Timestamp: {}, Source: {}", e.getClass().getSimpleName(), e.getSessionId(), e.getTimestamp(), e.getSource());
    }

    @EventListener
    public void sessionDestroyedEvent(final @NotNull SessionDestroyedEvent e) {
        log.info("SessionEventListener.sessionDestroyedEvent, Event: {}, ID: {}, Timestamp: {}, Source: {}", e.getClass().getSimpleName(), e.getSessionId(), e.getTimestamp(), e.getSource());
    }

    @EventListener
    public void sessionDeletedEvent(final @NotNull SessionDeletedEvent e) {
        log.info("SessionEventListener.sessionDeletedEvent, Event: {}, ID: {}, Timestamp: {}, Source: {}", e.getClass().getSimpleName(), e.getSessionId(), e.getTimestamp(), e.getSource());
    }
}
