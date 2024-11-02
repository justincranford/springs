package com.github.justincranford.springs.authenticationorm.users.session;

import java.time.Duration;
import java.time.Instant;
import java.util.Set;

import org.springframework.session.Session;
import org.springframework.session.SessionRepository;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import com.github.justincranford.springs.util.basic.Base64Util;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Repository
@RequiredArgsConstructor
@Slf4j
@SuppressWarnings({"nls"})
public class SessionRepositoryFacade implements SessionRepository<SessionRepositoryFacade.SessionImpl> {
    private final SessionOrmRepository sessionOrmRepository;

    @Override
    public SessionImpl createSession() {
        return null;//SessionOrm.builder().build();
    }

    @Transactional
    @Override
    public void save(final SessionImpl sessionOrm) {
//        this.sessionOrmRepository.save(sessionOrm);
    }

    @Transactional
    @Override
    public SessionImpl findById(final String externalIdBase64Url) {
//        final byte[] externalIdBytes = Base64Util.URL.decodeFromString(externalIdBase64Url);
//		return this.sessionOrmRepository.findByExternalId(externalIdBytes).orElse(null);
		return null;
    }

	@Transactional
    @Override
    public void deleteById(final String externalIdBase64Url) {
        final byte[] externalIdBytes = Base64Util.URL.decodeFromString(externalIdBase64Url);
		final Long id = this.sessionOrmRepository.getIdByExternalId(externalIdBytes).orElse(null);
		if (id == null) {
			log.warn("Session not found for externalId: {}", externalIdBase64Url);
		} else {
			log.warn("Session found for externalId: {}", externalIdBase64Url);
	        this.sessionOrmRepository.deleteById(id);
		}
    }
	public static class SessionImpl implements Session {
		@Override
		public String getId() {
			// TODO Auto-generated method stub
			return null;
		}

		@Override
		public String changeSessionId() {
			// TODO Auto-generated method stub
			return null;
		}

		@Override
		public <T> T getAttribute(String attributeName) {
			// TODO Auto-generated method stub
			return null;
		}

		@Override
		public Set<String> getAttributeNames() {
			// TODO Auto-generated method stub
			return null;
		}

		@Override
		public void setAttribute(String attributeName, Object attributeValue) {
			// TODO Auto-generated method stub
			
		}

		@Override
		public void removeAttribute(String attributeName) {
			// TODO Auto-generated method stub
			
		}

		@Override
		public Instant getCreationTime() {
			// TODO Auto-generated method stub
			return null;
		}

		@Override
		public void setLastAccessedTime(Instant lastAccessedTime) {
			// TODO Auto-generated method stub
			
		}

		@Override
		public Instant getLastAccessedTime() {
			// TODO Auto-generated method stub
			return null;
		}

		@Override
		public void setMaxInactiveInterval(Duration interval) {
			// TODO Auto-generated method stub
			
		}

		@Override
		public Duration getMaxInactiveInterval() {
			// TODO Auto-generated method stub
			return null;
		}

		@Override
		public boolean isExpired() {
			// TODO Auto-generated method stub
			return false;
		}
	}
}