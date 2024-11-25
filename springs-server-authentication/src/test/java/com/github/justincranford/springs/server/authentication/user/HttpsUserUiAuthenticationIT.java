package com.github.justincranford.springs.server.authentication.user;

import com.github.justincranford.springs.persistenceorm.users.properties.SpringsPersistenceOrmUsersPeopleProperties;
import com.github.justincranford.springs.persistenceorm.users.properties.SpringsPersistenceOrmUsersPeopleProperties.Person.Persona;
import com.github.justincranford.springs.persistenceorm.users.properties.SpringsPersistenceOrmUsersPeopleProperties.Person.Persona.EmailAddress;
import com.github.justincranford.springs.server.authentication.AbstractIT;
import com.github.justincranford.springs.util.http.client.util.RestTemplateUtil;
import lombok.extern.slf4j.Slf4j;
import org.htmlunit.WebClient;
import org.htmlunit.html.HtmlButton;
import org.htmlunit.html.HtmlForm;
import org.htmlunit.html.HtmlHiddenInput;
import org.htmlunit.html.HtmlPage;
import org.htmlunit.html.HtmlPasswordInput;
import org.htmlunit.html.HtmlTextInput;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.RepeatedTest;
import org.springframework.http.HttpStatus;
import org.springframework.web.client.RestTemplate;

import javax.net.ssl.SSLContext;
import java.util.List;

import static java.util.Objects.requireNonNull;
import static org.assertj.core.api.Assertions.assertThat;

@Slf4j
public class HttpsUserUiAuthenticationIT extends AbstractIT {
	private static final int REPEATS = 1;

	@Nested
	public class HttpsLoginRedirectWhenUnauthenticated {
		@RepeatedTest(REPEATS)
		void stls() {
			attemptUnauthenticatedHttpGet(stlsRestTemplate());
		}
		@RepeatedTest(REPEATS)
		void mtls() {
			attemptUnauthenticatedHttpGet(mtlsRestTemplate());
		}
	}

	@Nested
	public class HttpsLoginPersonaEmail {
		@Nested
		public class Success {
			@RepeatedTest(REPEATS)
			void sTls() throws Exception {
				attemptLoginPersonaEmail(stlsSslContext(), true);
			}
			@RepeatedTest(REPEATS)
			void mTls() throws Exception {
				attemptLoginPersonaEmail(mtlsSslContext(), true);
			}
		}

		@Nested
		public class Failure {
			@RepeatedTest(REPEATS)
			void sTls() throws Exception {
				attemptLoginPersonaEmail(stlsSslContext(), false);
			}
			@RepeatedTest(REPEATS)
			void mTls() throws Exception {
				attemptLoginPersonaEmail(mtlsSslContext(), false);
			}
		}
	}

	@Nested
	public class HttpsLoginPersonUsername {
		@Nested
		public class Success {
			@RepeatedTest(REPEATS)
			void sTls() throws Exception {
				attemptLoginPersonUsername(stlsSslContext(), true);
			}
			@RepeatedTest(REPEATS)
			void mTls() throws Exception {
				attemptLoginPersonUsername(mtlsSslContext(), true);
			}
		}

		@Nested
		public class Failure {
			@RepeatedTest(REPEATS)
			void sTls() throws Exception {
				attemptLoginPersonUsername(stlsSslContext(), false);
			}
			@RepeatedTest(REPEATS)
			void mTls() throws Exception {
				attemptLoginPersonUsername(mtlsSslContext(), false);
			}
		}
	}

	//<form class="form-signin" method="post" action="/login">
	// <input type="text" id="username" name="username" class="form-control" placeholder="Username" required="" autofocus=""/>
	// <input type="password" id="password" name="password" class="form-control" placeholder="Password" required=""/>
	// <input name="_csrf" type="hidden" value="JmqZF4H33AOhG1U5tBnEWzQWH0Zt7OI8UOIyqK7505Koa8ZRFlr7LuKV62eMKGQJ0TTwa1YjMiQPjtERMYELkcjPtqGeCv9h"/>
	// <button class="btn btn-lg btn-primary btn-block" type="submit">
	@edu.umd.cs.findbugs.annotations.SuppressFBWarnings(value="DLS_DEAD_LOCAL_STORE",justification="Design intent for clarity")
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

	private void attemptUnauthenticatedHttpGet(final RestTemplate httpsRestTemplate) {
		final String response = RestTemplateUtil.plainGet(httpsRestTemplate, httpsBaseUrl() + "/secure/home", null, String.class);
		assertThat(response).contains("action=\"/login\"");
	}

	private void attemptLoginPersonaEmail(final SSLContext sslContext, final boolean assertLoginSuccess) throws Exception {
		final List<SpringsPersistenceOrmUsersPeopleProperties.Person> people = springsPersistenceOrmUsersPeopleProperties().getPeople();
        Assertions.assertFalse(people.isEmpty());
		final SpringsPersistenceOrmUsersPeopleProperties.Person person = people.getFirst();
		final List<Persona> personas = person.getPersonas();
        Assertions.assertFalse(personas.isEmpty());
		final Persona persona = personas.getFirst();
		final List<EmailAddress> emailAddresses = persona.getEmailAddresses();
        Assertions.assertFalse(emailAddresses.isEmpty());
		final EmailAddress emailAddress = emailAddresses.getFirst();
		final boolean success = attemptUiLogin(sslContext, emailAddress.getEmailAddress(), assertLoginSuccess ? person.getPassword() : "Wrong");
		if (assertLoginSuccess) {
			Assertions.assertTrue(success);
		} else {
			Assertions.assertFalse(success);
		}
	}

	private void attemptLoginPersonUsername(final SSLContext sslContext, final boolean assertLoginSuccess) throws Exception {
		final List<SpringsPersistenceOrmUsersPeopleProperties.Person> people = springsPersistenceOrmUsersPeopleProperties().getPeople();
        Assertions.assertFalse(people.isEmpty());
		final SpringsPersistenceOrmUsersPeopleProperties.Person person = people.getFirst();
		final boolean success = attemptUiLogin(sslContext, person.getUsername(), assertLoginSuccess ? person.getPassword() : "Wrong");
		if (assertLoginSuccess) {
			Assertions.assertTrue(success);
		} else {
			Assertions.assertFalse(success);
		}
	}
}
