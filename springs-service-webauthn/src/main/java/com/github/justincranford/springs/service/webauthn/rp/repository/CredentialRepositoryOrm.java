package com.github.justincranford.springs.service.webauthn.rp.repository;

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
import com.yubico.webauthn.data.PublicKeyCredentialType;

import lombok.extern.slf4j.Slf4j;

@Slf4j
@SuppressWarnings({ "nls" })
public class CredentialRepositoryOrm implements CredentialRepository {
	private final Cache<String, Set<RegisteredCredential>> storage = CacheBuilder.newBuilder()
		.maximumSize(1000)
		.expireAfterAccess(1, TimeUnit.DAYS)
		.build();

	@Override
	public Set<PublicKeyCredentialDescriptor> getCredentialIdsForUsername(final String username) {
		final Set<RegisteredCredential> registeredCredentials = this.storage.getIfPresent(username);
        if (registeredCredentials == null) {
            return Set.of();
        }
        final Set<PublicKeyCredentialDescriptor> publicKeyCredentialDescriptors = registeredCredentials
        	.stream()
            .map(registeredCredential ->
            	PublicKeyCredentialDescriptor.builder()
                    .id(registeredCredential.getCredentialId())
                    .type(PublicKeyCredentialType.PUBLIC_KEY)
                    .build()
            )
            .collect(Collectors.toSet());

		log.debug("lookup username: {}, publicKeyCredentialDescriptors: {}", username, publicKeyCredentialDescriptors);
		return publicKeyCredentialDescriptors;
	}

	@Override
	public Optional<String> getUsernameForUserHandle(final ByteArray userHandle) {
		final Optional<String> optionalUsername = this.storage.asMap().entrySet().stream()
			.filter(usernameToRegisteredCredentials -> {
				for (final RegisteredCredential registeredCredential : usernameToRegisteredCredentials.getValue()) {
					if (userHandle.equals(registeredCredential.getUserHandle())) {
						return true;
					}
				}
				return false;
			})
			.map(usernameToRegisteredCredentials -> usernameToRegisteredCredentials.getKey())
			.findAny();
			log.debug("lookup user handle: {}; optionalUsername: {}", userHandle, optionalUsername);
			return optionalUsername;
	}

	@Override
	public Optional<ByteArray> getUserHandleForUsername(final String username) {
		final Set<RegisteredCredential> registeredCredentials = this.storage.getIfPresent(username);
        if (registeredCredentials == null) {
            return Optional.empty();
        }
        final Set<ByteArray> userHandles = registeredCredentials
        	.stream()
            .map(registeredCredential -> registeredCredential.getUserHandle())
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
		final Optional<RegisteredCredential> optionalRegisteredCredential = this.storage
			.asMap().values().stream().flatMap(Collection::stream)
			.filter(registeredCredential ->
				credentialId.equals(registeredCredential.getCredentialId()) &&
				userHandle.equals(registeredCredential.getUserHandle())
			)
			.findAny();
		log.debug("lookup credential ID: {}, user handle: {}; optionalRegisteredCredential: {}", credentialId, userHandle, optionalRegisteredCredential);
		return optionalRegisteredCredential;
	}

	@Override
	public Set<RegisteredCredential> lookupAll(final ByteArray credentialId) {
		final Set<RegisteredCredential> registeredCredentials = this.storage
			.asMap().values().stream().flatMap(Collection::stream)
			.filter(registeredCredential ->
				credentialId.equals(registeredCredential.getCredentialId())
			)
			.collect(Collectors.toSet());
			log.debug("lookup credential ID: {}, optionalRegisteredCredentials: {}", credentialId, registeredCredentials);
			return registeredCredentials;
	}

//	@Override
//	public Set<RegisteredCredential> getCredentialDescriptorsForUserHandle(ByteArray userHandle) {
//		return getRegistrationsByUserHandle(userHandle);
//	}
//
//	@Override
//	public Optional<RegisteredCredential> lookup(ByteArray credentialId, ByteArray userHandle) {
//		Optional<RegisteredCredential> registrationMaybe = storage.asMap().values().stream()
//				.flatMap(Collection::stream)
//				.filter(credReg -> credentialId.equals(credReg.getCredential().getCredentialId())
//						&& userHandle.equals(credReg.getUserHandle()))
//				.findAny();
//
//		log.debug("lookup credential ID: {}, user handle: {}; result: {}", credentialId, userHandle, registrationMaybe);
//
//		return registrationMaybe;
//	}
//
//	@Override
//	public boolean credentialIdExists(ByteArray credentialId) {
//		return storage.asMap().values().stream().flatMap(Collection::stream)
//				.anyMatch(reg -> reg.getCredential().getCredentialId().equals(credentialId));
//	}

	public boolean addRegistrationByUsername(final String username, final RegisteredCredential registeredCredential) {
		try {
			return this.storage.get(username, HashSet::new).add(registeredCredential);
		} catch (ExecutionException e) {
			log.error("Failed to add registration", e);
			throw new RuntimeException(e);
		}
	}

	public Set<RegisteredCredential> getRegistrationsByUsername(String username) {
		try {
			return this.storage.get(username, HashSet::new);
		} catch (ExecutionException e) {
			log.error("Registration lookup failed", e);
			throw new RuntimeException(e);
		}
	}

	public Set<RegisteredCredential> getRegistrationsByUserHandle(final ByteArray userHandle) {
		final Set<RegisteredCredential> registeredCredentials = this.storage
				.asMap().values().stream().flatMap(Collection::stream)
				.filter(registeredCredential ->
					userHandle.equals(registeredCredential.getUserHandle())
				)
				.collect(Collectors.toSet());
			log.debug("lookup credential ID: {}, user handle: {}; optionalRegisteredCredential: {}", userHandle, registeredCredentials);
			return registeredCredentials;
	}

	public Optional<RegisteredCredential> getRegistrationByUsernameAndCredentialId(String username, ByteArray id) {
		try {
			return this.storage.get(username, HashSet::new).stream().filter(credReg -> id.equals(credReg.getCredentialId())).findFirst();
		} catch (ExecutionException e) {
			log.error("Registration lookup failed", e);
			throw new RuntimeException(e);
		}
	}

	public boolean removeRegistrationByUsername(String username, RegisteredCredential credentialRegistration) {
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
		return !getRegistrationsByUsername(username).isEmpty();
	}
}