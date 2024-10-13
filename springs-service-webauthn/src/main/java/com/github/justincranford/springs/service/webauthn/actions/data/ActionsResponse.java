package com.github.justincranford.springs.service.webauthn.actions.data;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;

import com.fasterxml.jackson.annotation.JsonProperty;

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
public final class ActionsResponse {
	private Actions actions;
	private Info info;

	public ActionsResponse(final String url) throws MalformedURLException {
		final String slash = url.endsWith("/") ? "" : "/";
		this.actions = new Actions(url + slash);
		this.info    = new Info(url + slash);
	}

	//@Accessors(fluent = true)
	@AllArgsConstructor
	@NoArgsConstructor
	@Getter(onMethod = @__(@JsonProperty))
	@Setter
	@ToString
	@EqualsAndHashCode
	@Builder(toBuilder=true)
	public static final class Actions {
		private URL authenticate;
		private URL deleteAccount;
		private URL deregister;
		private URL register;

		public Actions(final String url) throws MalformedURLException {
			this.authenticate  = URI.create(url + "authenticate").toURL();
			this.deleteAccount = URI.create(url + "delete-account").toURL();
			this.deregister    = URI.create(url + "action/deregister").toURL();
			this.register      = URI.create(url + "register").toURL();
		}
	}

	//@Accessors(fluent = true)
	@AllArgsConstructor
	@NoArgsConstructor
	@Getter(onMethod = @__(@JsonProperty))
	@Setter
	@ToString
	@EqualsAndHashCode
	@Builder(toBuilder=true)
	public static final class Info {
		private URL version;

		public Info(final String url) throws MalformedURLException {
			this.version = URI.create(url + "version").toURL();
		}
	}
}
