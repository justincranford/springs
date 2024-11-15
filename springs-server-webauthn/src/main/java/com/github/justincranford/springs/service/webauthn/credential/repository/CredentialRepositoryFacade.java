package com.github.justincranford.springs.service.webauthn.credential.repository;

import java.security.MessageDigest;
import java.util.LinkedHashSet;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import com.yubico.webauthn.CredentialRepository;
import com.yubico.webauthn.RegisteredCredential;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.PublicKeyCredentialDescriptor;

@Component
public class CredentialRepositoryFacade implements CredentialRepository {
	@Autowired
	private CredentialRepositoryOrm credentialRepositoryOrm;
	@Autowired
	private UserIdentityRepositoryOrm userIdentityRepositoryOrm;

	@Override
	public Optional<String> getUsernameForUserHandle(final ByteArray userHandle) {
		return this.userIdentityRepositoryOrm.findByUserHandle(userHandle.getBytes()).map(userIdentityOrm -> userIdentityOrm.username());
	}

	@Override
	public Optional<ByteArray> getUserHandleForUsername(final String username) {
		return this.userIdentityRepositoryOrm.findByUsername(username).map(userIdentityOrm -> new ByteArray(userIdentityOrm.userHandle()));
	}

	@Override
	public Set<PublicKeyCredentialDescriptor> getCredentialIdsForUsername(final String username) {
	    return this.userIdentityRepositoryOrm.findByUsername(username)
    		.map(userIdentityOrm -> 
		        this.credentialRepositoryOrm.findByUserIdentityOrderByCreatedDateDesc(userIdentityOrm)
		            .stream()
		            .map(CredentialOrm::toPublicKeyCredentialDescriptor)
		            .collect(Collectors.toCollection(LinkedHashSet::new))
	        )
	        .orElseGet(LinkedHashSet::new);			
	}

	@Override
	public Optional<RegisteredCredential> lookup(final ByteArray credentialId, final ByteArray userHandle) {
	    return this.credentialRepositoryOrm.findByCredentialIdOrderByCreatedDateDesc(credentialId.getBase64Url())
    		.stream()
    		.filter(credentialOrm -> MessageDigest.isEqual(credentialOrm.userIdentity().userHandle(), userHandle.getBytes()))
    		.map(CredentialOrm::toRegisteredCredential)
    		.findFirst();
	}

	@Override
	public Set<RegisteredCredential> lookupAll(final ByteArray credentialId) {
        return this.credentialRepositoryOrm.findByCredentialIdOrderByCreatedDateDesc(credentialId.getBase64Url())
    		.stream()
    		.map(CredentialOrm::toRegisteredCredential)
            .collect(Collectors.toCollection(LinkedHashSet::new));
	}
}