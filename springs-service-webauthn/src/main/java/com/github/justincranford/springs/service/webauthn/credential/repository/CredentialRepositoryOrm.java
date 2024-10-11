package com.github.justincranford.springs.service.webauthn.credential.repository;

import static com.github.justincranford.springs.service.webauthn.util.ByteArrayUtil.decodeBase64Url;

import java.util.Collection;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import com.yubico.webauthn.CredentialRepository;
import com.yubico.webauthn.RegisteredCredential;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.PublicKeyCredentialDescriptor;

import lombok.extern.slf4j.Slf4j;

@Slf4j
@SuppressWarnings({ "nls" })
public class CredentialRepositoryOrm implements CredentialRepository {
	private final Cache<String, Set<CredentialOrm>> storage = CacheBuilder.newBuilder()
		.maximumSize(1000)
		.expireAfterAccess(1, TimeUnit.DAYS)
		.build();

	@Override
	public Set<PublicKeyCredentialDescriptor> getCredentialIdsForUsername(final String username) {
		final Set<CredentialOrm> credentialOrms = this.storage.getIfPresent(username);
        if (credentialOrms == null) {
            return Set.of();
        }
        final Set<PublicKeyCredentialDescriptor> publicKeyCredentialDescriptors = credentialOrms.stream()
            .map(CredentialOrm::toPublicKeyCredentialDescriptor)
            .collect(Collectors.toSet());
		log.debug("lookup username: {}, publicKeyCredentialDescriptors: {}", username, publicKeyCredentialDescriptors);
		return publicKeyCredentialDescriptors;
	}

	@Override
	public Optional<String> getUsernameForUserHandle(final ByteArray userHandle) {
		final Optional<String> optionalUsername = this.storage.asMap().entrySet().stream()
			.filter(usernameToCredentialOrms -> {
				for (final CredentialOrm credentialOrm : usernameToCredentialOrms.getValue()) {
					if (userHandle.equals(decodeBase64Url(credentialOrm.getUserHandle()))) {
						return true;
					}
				}
				return false;
			})
			.map(usernameToCredentialOrms -> usernameToCredentialOrms.getKey())
			.findAny();
		log.debug("lookup user handle: {}; optionalUsername: {}", userHandle, optionalUsername);
		return optionalUsername;
	}

	@Override
	public Optional<ByteArray> getUserHandleForUsername(final String username) {
		final Set<CredentialOrm> oredentialOrms = this.storage.getIfPresent(username);
        if (oredentialOrms == null) {
            return Optional.empty();
        }
        final Set<ByteArray> userHandles = oredentialOrms.stream()
            .map(CredentialOrm::getUserHandle)
            .map(x -> decodeBase64Url(x))
            .collect(Collectors.toSet());
        if (userHandles.isEmpty()) {
        	throw new InternalError("No userHandles found for username");
        } else if (userHandles.size() > 1) {
        	throw new InternalError("Duplicate userHandles found for username");
        }
		log.debug("lookup username: {}, userHandles: {}", username, userHandles);
		return Optional.of(userHandles.iterator().next());
	}

	@Override
	public Optional<RegisteredCredential> lookup(final ByteArray credentialId, final ByteArray userHandle) {
		final Optional<RegisteredCredential> optionalCredentialOrm = this.storage
			.asMap().values().stream().flatMap(Collection::stream)
			.filter(credentialOrm ->
				credentialId.getBase64Url().equals(credentialOrm.getCredentialId()) &&
				userHandle.getBase64Url().equals(credentialOrm.getUserHandle())
			)
			.map(CredentialOrm::toRegisteredCredential)
			.findAny();
		log.debug("lookup credential ID: {}, user handle: {}; optionalCredentialOrm: {}", credentialId, userHandle, optionalCredentialOrm);
		return optionalCredentialOrm;
	}

	@Override
	public Set<RegisteredCredential> lookupAll(final ByteArray credentialId) {
		final Set<RegisteredCredential> credentialOrms = this.storage
			.asMap().values().stream().flatMap(Collection::stream)
			.filter(credentialOrm ->
				credentialId.getBase64Url().equals(credentialOrm.getCredentialId())
			)
			.map(CredentialOrm::toRegisteredCredential)
			.collect(Collectors.toSet());
			log.debug("lookup credential ID: {}, optionalCredentialOrms: {}", credentialId, credentialOrms);
			return credentialOrms;
	}

	public Set<CredentialOrm> getCredentialDescriptorsForUserHandle(ByteArray userHandle) {
		return getRegistrationsByUserHandle(userHandle);
	}

	public boolean credentialIdExists(ByteArray credentialId) {
	final String base64Url = credentialId.getBase64Url();
		return this.storage.asMap().values().stream().flatMap(Collection::stream)
			.anyMatch(reg -> reg.getCredentialId().equals(base64Url));
	}

	public boolean addByUsername(final String username, final CredentialOrm CredentialOrm) {
		try {
			return this.storage.get(username, HashSet::new).add(CredentialOrm);
		} catch (ExecutionException e) {
			log.error("Failed to add registration", e);
			throw new RuntimeException(e);
		}
	}

	public Set<CredentialOrm> getByUsername(String username) {
		try {
			return this.storage.get(username, HashSet::new);
		} catch (ExecutionException e) {
			log.error("Registration lookup failed", e);
			throw new RuntimeException(e);
		}
	}

	public Set<CredentialOrm> getRegistrationsByUserHandle(final ByteArray userHandle) {
		final Set<CredentialOrm> credentialOrms = this.storage
			.asMap().values().stream().flatMap(Collection::stream)
			.filter(credentialOrm ->
				userHandle.getBase64Url().equals(credentialOrm.getUserHandle())
			)
			.collect(Collectors.toSet());
		log.debug("lookup credential ID: {}, user handle: {}; optionalCredentialOrm: {}", userHandle, credentialOrms);
		return credentialOrms;
	}

	public Optional<CredentialOrm> getRegistrationByUsernameAndCredentialId(String username, ByteArray id) {
		try {
			final String credentialId = id.getBase64Url();
			return this.storage.get(username, HashSet::new).stream().filter(credReg -> credentialId.equals(credReg.getCredentialId())).findFirst();
		} catch (ExecutionException e) {
			log.error("Registration lookup failed", e);
			throw new RuntimeException(e);
		}
	}

	public boolean removeRegistrationByUsername(String username, CredentialOrm credentialRegistration) {
		try {
			return this.storage.get(username, HashSet::new).remove(credentialRegistration);
		} catch (ExecutionException e) {
			log.error("Failed to remove registration", e);
			throw new RuntimeException(e);
		}
	}

	public boolean removeAllRegistrations(String username) {
		this.storage.invalidate(username);
		return true;
	}

	public boolean userExists(String username) {
		return !getByUsername(username).isEmpty();
	}
}