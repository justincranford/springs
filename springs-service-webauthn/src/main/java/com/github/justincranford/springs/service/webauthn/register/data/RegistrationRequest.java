package com.github.justincranford.springs.service.webauthn.register.data;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.yubico.webauthn.data.PublicKeyCredentialCreationOptions;
import com.yubico.webauthn.data.UserIdentity;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;

//@Accessors(fluent = true)
@AllArgsConstructor
@NoArgsConstructor
@Getter(onMethod = @__(@JsonProperty))
@Setter
@ToString
@EqualsAndHashCode
@Builder(toBuilder=true)
@SuppressWarnings({"nls"})
public class RegistrationRequest {
	private boolean success;
	private UserIdentity userIdentity;
	private String username;
	private String displayName;
	private String credentialNickname;
	private String sessionToken;
	private Request request;
	private StartRegistrationActions actions;

	//@Accessors(fluent = true)
	@AllArgsConstructor
	@NoArgsConstructor
	@Getter(onMethod = @__(@JsonProperty))
	@Setter
	@ToString
	@EqualsAndHashCode
	@Builder(toBuilder=true)
	public static class Request {
		private PublicKeyCredentialCreationOptions publicKeyCredentialCreationOptions;
	}

	//@Accessors(fluent = true)
	@AllArgsConstructor
	@NoArgsConstructor
	@Getter(onMethod = @__(@JsonProperty))
	@Setter
	@ToString
	@EqualsAndHashCode
	@Builder(toBuilder=true)
	public static class StartRegistrationActions {
		public URL finish;

		public StartRegistrationActions(final String url) throws MalformedURLException {
			final String slash = url.endsWith("/") ? "" : "/";
			this.finish = URI.create(url + slash + "finish").toURL();
		}
	}
}
