package com.github.justincranford.springs.authenticationorm.users.authentication;

import static java.util.Objects.requireNonNull;
import static org.assertj.core.api.Assertions.assertThat;

import javax.net.ssl.SSLContext;

import org.htmlunit.WebClient;
import org.htmlunit.html.HtmlButton;
import org.htmlunit.html.HtmlForm;
import org.htmlunit.html.HtmlHiddenInput;
import org.htmlunit.html.HtmlPage;
import org.htmlunit.html.HtmlPasswordInput;
import org.htmlunit.html.HtmlTextInput;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;

import com.github.justincranford.springs.authenticationorm.users.AbstractIT;
import com.github.justincranford.springs.persistenceorm.users.person.PersonOrm;
import com.github.justincranford.springs.persistenceorm.users.properties.SpringsPersistenceOrmUsersPeopleProperties;
import com.github.justincranford.springs.service.http.client.RestTemplateUtil;
import com.github.justincranford.springs.util.basic.SecureRandomUtil;

import lombok.extern.slf4j.Slf4j;

@Slf4j
@SuppressWarnings({"nls"})
public class HttpsUiAuthenticationIT extends AbstractIT {
	@Test
	void testHttpsLoginRedirect_whenUnauthenticated() throws Exception {
		final String response = RestTemplateUtil.plainGet(stlsRestTemplate(), httpsBaseUrl() + "/secure/home", String.class);
		assertThat(response).contains("action=\"/login\"");
	}

	@RepeatedTest(2)
	void testHttpsLoginSuccess_personPassword_serverTls() throws Exception {
		final SpringsPersistenceOrmUsersPeopleProperties.Person person = SecureRandomUtil.randomListElement(springsPersistenceOrmUsersPeopleProperties().getPeople());
		final boolean success = attemptUiLogin(stlsSslContext(), person.getUsername(), person.getPassword()); // clear password from properties
		Assertions.assertTrue(success);
	}

	@RepeatedTest(2)
	void testHttpsLoginSuccess_personPassword_mutualTls() throws Exception {
		final SpringsPersistenceOrmUsersPeopleProperties.Person person = SecureRandomUtil.randomListElement(springsPersistenceOrmUsersPeopleProperties().getPeople());
		final boolean success = attemptUiLogin(mtlsSslContext(), person.getUsername(), person.getPassword()); // clear password from properties
		Assertions.assertTrue(success);
	}

	@RepeatedTest(2)
	void testHttps_unauthenticated() throws Exception {
		final PersonOrm personOrm = SecureRandomUtil.randomListElement(personOrmRepository().findAll());
		final boolean success = attemptUiLogin(stlsSslContext(), personOrm.username(), personOrm.password().password()); // hashed password from database
		Assertions.assertFalse(success);
	}

	//<form class="form-signin" method="post" action="/login">
	// <input type="text" id="username" name="username" class="form-control" placeholder="Username" required="" autofocus=""/>
	// <input type="password" id="password" name="password" class="form-control" placeholder="Password" required=""/>
	// <input name="_csrf" type="hidden" value="JmqZF4H33AOhG1U5tBnEWzQWH0Zt7OI8UOIyqK7505Koa8ZRFlr7LuKV62eMKGQJ0TTwa1YjMiQPjtERMYELkcjPtqGeCv9h"/>
	// <button class="btn btn-lg btn-primary btn-block" type="submit">
	private boolean attemptUiLogin(final SSLContext sslContext, final String username, final String password) throws Exception {
		try (final WebClient webClient = new WebClient()) {
			webClient.getOptions().setSSLContext(sslContext);
			webClient.getOptions().setCssEnabled(false);
			webClient.getOptions().setJavaScriptEnabled(false);

            final HtmlPage loginPage = webClient.getPage(httpsBaseUrl() + "/login");
			assertThat(loginPage.getWebResponse().getStatusCode()).isEqualTo(HttpStatus.OK.value());

			final String loginPageAsXml = loginPage.asXml();
			log.info("Login page as XML:\n{}", loginPageAsXml);
			final String loginPageTitleText = loginPage.getTitleText();
			Assertions.assertTrue(loginPageTitleText.contains("Please sign in"));

			final HtmlForm loginForm = requireNonNull(loginPage.getForms().getFirst());

			final HtmlTextInput     usernameField = requireNonNull(loginForm.getInputByName("username"));
			final HtmlPasswordInput passwordField = requireNonNull(loginForm.getInputByName("password"));
			@SuppressWarnings("unused")
			final HtmlHiddenInput   csrfField     = requireNonNull(loginForm.getInputByName("_csrf"));
//			final HtmlButton        loginButton   = requireNonNull(loginForm.getButtonsByName("submit")).getFirst();
			final HtmlButton        loginButton   = (HtmlButton) loginForm.getFirstByXPath("//button[@class='btn btn-lg btn-primary btn-block']");

			usernameField.type(username);
			passwordField.type(password);

			final HtmlPage loggedInPage = loginButton.click();
			assertThat(loggedInPage.getWebResponse().getStatusCode()).isEqualTo(HttpStatus.OK.value());

			final String loggedInPageAsXml = loggedInPage.asXml();
			log.info("Logged in page as XML:\n{}", loggedInPageAsXml);
			final String loggedInPageTitleText = loggedInPage.getTitleText();
			return loggedInPageTitleText.contains("Secure Home");
		}
	}
}
