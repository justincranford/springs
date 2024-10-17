package com.github.justincranford.springs.service.webauthn.credential.repository;

import java.util.List;
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
		final List<CredentialOrm> credentialOrms = this.credentialRepositoryOrm.findByUsernameOrderByCreatedDateDesc(username);
        return credentialOrms.stream().map(CredentialOrm::toPublicKeyCredentialDescriptor).collect(Collectors.toSet());
	}

	@Override
	public Optional<RegisteredCredential> lookup(final ByteArray credentialId, final ByteArray userHandle) {
		final List<CredentialOrm> credentialOrms = this.credentialRepositoryOrm.findByCredentialIdAndUserHandleOrderByCreatedDateDesc(credentialId.getBase64Url(), userHandle.getBase64Url());
        return credentialOrms.stream().map(CredentialOrm::toRegisteredCredential).findAny();
	}

	@Override
	public Set<RegisteredCredential> lookupAll(final ByteArray credentialId) {
		final List<CredentialOrm> credentialOrms = this.credentialRepositoryOrm.findByCredentialIdOrderByCreatedDateDesc(credentialId.getBase64Url());
        return credentialOrms.stream().map(CredentialOrm::toRegisteredCredential).collect(Collectors.toSet());
	}
}