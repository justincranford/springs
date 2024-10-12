package com.github.justincranford.springs.service.webauthn.register.data;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonInclude;
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
@AllArgsConstructor(onConstructor = @__(@JsonCreator))
@NoArgsConstructor(onConstructor = @__(@JsonCreator))
@Getter(onMethod = @__(@JsonProperty))
@Setter(onMethod = @__(@JsonProperty))
@ToString
@EqualsAndHashCode(callSuper = false)
@Builder(toBuilder=true)
@SuppressWarnings({"nls"})
public class RegistrationRequest {
	@Builder.Default
	private boolean success = true;
	private UserIdentity userIdentity;
	private String username;
	private String displayName;
	private String credentialNickname;
	private String sessionToken;
	private Request request;
	private StartRegistrationActions actions;

	//@Accessors(fluent = true)
	@AllArgsConstructor(onConstructor = @__(@JsonCreator))
	@NoArgsConstructor(onConstructor = @__(@JsonCreator))
	@Getter(onMethod = @__(@JsonProperty))
	@Setter
	@ToString
	@EqualsAndHashCode(callSuper = false)
	@Builder(toBuilder=true)
	public static class Request {
		@JsonInclude(JsonInclude.Include.NON_NULL)
		private PublicKeyCredentialCreationOptions publicKeyCredentialCreationOptions;
	}

	//@Accessors(fluent = true)
	@AllArgsConstructor(onConstructor = @__(@JsonCreator))
	@NoArgsConstructor(onConstructor = @__(@JsonCreator))
	@Getter(onMethod = @__(@JsonProperty))
	@Setter(onMethod = @__(@JsonProperty))
	@ToString
	@EqualsAndHashCode(callSuper = false)
	@Builder(toBuilder=true)
	public static class StartRegistrationActions {
		public URL finish;

		public StartRegistrationActions(final String url) throws MalformedURLException {
			final String slash = url.endsWith("/") ? "" : "/";
			this.finish = URI.create(url + slash + "finish").toURL();
		}
	}
}
