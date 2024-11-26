package com.github.justincranford.springs.persistenceredis.sessions.listener;

import jakarta.annotation.PostConstruct;
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
public class SessionEventListener {
    @PostConstruct
    public void postConstruct() {
        log.info("SessionEventListener.postConstruct");
    }

    @EventListener
    public void sessionCreatedEvent(final @NotNull SessionCreatedEvent e) {
        if (log.isDebugEnabled()) {
            log.debug("SessionEventListener.sessionCreatedEvent, Event: {}, ID: {}, Timestamp: {}, Source: {}, Event: {}", e.getClass().getSimpleName(), e.getSessionId(), e.getTimestamp(), e.getSource(), e);
        } else {
            log.info("SessionEventListener.sessionCreatedEvent, Event: {}, ID: {}, Timestamp: {}, Source: {}", e.getClass().getSimpleName(), e.getSessionId(), e.getTimestamp(), e.getSource());
        }
    }

    @EventListener
    public void sessionIdChangedEvent(final @NotNull SessionIdChangedEvent e) {
        if (log.isDebugEnabled()) {
            log.debug("SessionEventListener.sessionIdChangedEvent, Event: {}, New ID: {}, Old ID: {}, Timestamp: {}, Source: {}, Event: {}", e.getClass().getSimpleName(), e.getNewSessionId(), e.getOldSessionId(), e.getTimestamp(), e.getSource(), e);
        } else {
            log.info("SessionEventListener.sessionIdChangedEvent, Event: {}, New ID: {}, Old ID: {}, Timestamp: {}, Source: {}", e.getClass().getSimpleName(), e.getNewSessionId(), e.getOldSessionId(), e.getTimestamp(), e.getSource());
        }
    }

    @EventListener
    public void sessionExpiredEvent(final @NotNull SessionExpiredEvent e) {
        if (log.isDebugEnabled()) {
            log.debug("SessionEventListener.sessionExpiredEvent, Event: {}, ID: {}, Timestamp: {}, Source: {}, Event: {}", e.getClass().getSimpleName(), e.getSessionId(), e.getTimestamp(), e.getSource(), e);
        } else {
            log.info("SessionEventListener.sessionExpiredEvent, Event: {}, ID: {}, Timestamp: {}, Source: {}", e.getClass().getSimpleName(), e.getSessionId(), e.getTimestamp(), e.getSource());
        }
    }

    @EventListener
    public void sessionDestroyedEvent(final @NotNull SessionDestroyedEvent e) {
        if (log.isDebugEnabled()) {
            log.debug("SessionEventListener.sessionDestroyedEvent, Event: {}, ID: {}, Timestamp: {}, Source: {}, Event: {}", e.getClass().getSimpleName(), e.getSessionId(), e.getTimestamp(), e.getSource(), e);
        } else {
            log.info("SessionEventListener.sessionDestroyedEvent, Event: {}, ID: {}, Timestamp: {}, Source: {}", e.getClass().getSimpleName(), e.getSessionId(), e.getTimestamp(), e.getSource());
        }
    }

    @EventListener
    public void sessionDeletedEvent(final @NotNull SessionDeletedEvent e) {
        if (log.isDebugEnabled()) {
            log.debug("SessionEventListener.sessionDeletedEvent, Event: {}, ID: {}, Timestamp: {}, Source: {}, Event: {}", e.getClass().getSimpleName(), e.getSessionId(), e.getTimestamp(), e.getSource(), e);
        } else {
            log.info("SessionEventListener.sessionDeletedEvent, Event: {}, ID: {}, Timestamp: {}, Source: {}", e.getClass().getSimpleName(), e.getSessionId(), e.getTimestamp(), e.getSource());
        }
    }
}
