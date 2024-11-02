package com.github.justincranford.springs.authenticationorm.users;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

import org.apache.hc.core5.http.NoHttpResponseException;
import org.assertj.core.api.AbstractThrowableAssert;
import org.assertj.core.api.Assertions;
import org.assertj.core.api.Fail;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.client.HttpClientErrorException;

import com.github.justincranford.springs.authenticationorm.users.authentication.provider.PersonUsernamePasswordAuthenticationProvider;
import com.github.justincranford.springs.authenticationorm.users.authentication.provider.PersonaEmailPasswordAuthenticationProvider;
import com.github.justincranford.springs.authenticationorm.users.authentication.service.model.PersonaDetails;
import com.github.justincranford.springs.authenticationorm.users.authentication.token.PersonaEmailPasswordAuthenticatedToken;
import com.github.justincranford.springs.persistenceorm.users.person.PersonOrm;
import com.github.justincranford.springs.persistenceorm.users.persona.PersonaOrm;
import com.github.justincranford.springs.persistenceorm.users.persona.enums.PersonaType;
import com.github.justincranford.springs.service.http.client.RestTemplateUtil;
import com.github.justincranford.springs.service.http.server.HelloWorldController;

@SuppressWarnings({"nls"})
public class SpringsAuthenticationOrmUsersSecurityFilterChainConfigurationIT extends AbstractIT {
    @Test
    void test0() throws Exception {
		RestTemplateUtil.anyGet(stlsRestTemplate(), httpsBaseUrl() + "/", String.class);
	}

    @Test
    void test1() throws Exception {
		RestTemplateUtil.anyGet(stlsRestTemplate(), httpsBaseUrl() + "/login", String.class);
	}

    @Test
    void test3() throws Exception {
		RestTemplateUtil.anyGet(stlsRestTemplate(), httpsBaseUrl() + "/logout", String.class);
	}

    @Test
    void test4() throws Exception {
		RestTemplateUtil.anyGet(stlsRestTemplate(), httpsBaseUrl() + "/notfound", String.class);
	}

    @Test
    void test5() throws Exception {
		RestTemplateUtil.anyGet(stlsRestTemplate(), httpsBaseUrl() + "/secure/notfound", String.class);
	}

    @Test
    void test6() throws Exception {
		RestTemplateUtil.anyGet(stlsRestTemplate(), httpsBaseUrl() + "/helloworld", String.class);
	}

    @Test
    void testSecureUnauthenticatedRedirectsLogin() throws Exception {
		final AbstractThrowableAssert<?, ? extends Throwable> assertThatThrownBy = assertThatThrownBy(
			() -> RestTemplateUtil.anyGet(stlsRestTemplate(), httpBaseUrl() + "/secure/notfound", String.class)
		);
		final String webServerClassName = webServerApplicationContext().getWebServer().getClass().getName();
		if (webServerClassName.contains("Tomcat")) {
			assertThatThrownBy
				.isInstanceOf(RuntimeException.class)
				.hasMessage("HTTP Error Response: [404 NOT_FOUND]")
				.cause()
				.isInstanceOf(HttpClientErrorException.class)
				.hasMessage("404 : \"Not found<EOL><EOL>XXXXXXXXXXXXXXXXXXXX<EOL><EOL>\"");
		} else if (webServerClassName.contains("Jetty")) {
			assertThatThrownBy
				.isInstanceOf(RuntimeException.class)
				.hasMessage("I/O error on GET request for \"http://localhost:8443/secure/notfound\": localhost:8443 failed to respond")
				.cause()
				.isInstanceOf(NoHttpResponseException.class)
				.hasMessage("localhost:8443 failed to respond");
		} else {
			Fail.fail("Unsupported webserver class: {}", webServerClassName);
		}
    }

//    @Test
//    @WithMockUser
//    void testSecureAuthenticatedNotFound() throws Exception {
//        mockMvc.perform(get("/secure/test"))
//        	.andExpect(status().isNotFound());
//    }
//
//    @Test
//    void testPublicUnauthenticatedNotFound() throws Exception {
//        mockMvc.perform(get("/static/test")).andExpect(status().isNotFound());
//    }
//
//    @Test
//    void testPublicHelloWorld() throws Exception {
//        mockMvc.perform(get("/helloworld")).andExpect(status().isOk());
//    }
//
//    @Test
//    void testAuthenticatedEndpointsAreAccessible() throws Exception {
//        mockMvc.perform(get("/v1/api/someProtectedEndpoint")).andExpect(status().isOk());
//    }
//
//    @Test
//    void testProtectedEndpointRequiresAuthentication() throws Exception {
//        mockMvc.perform(get("/v1/api/someProtectedEndpoint")).andExpect(status().isUnauthorized());
//    }
//
//    @Test
//    void testPersonaEmailAuthenticationProvider() {
//        // Given
//    	final PersonOrm personOrm = mock(PersonOrm.class);
//		final PersonaOrm personaOrm = mock(PersonaOrm.class);
//    	when(personaOrm.personaType()).thenReturn(PersonaType.ADM);
//		final PersonaDetails personaDetails = new PersonaDetails("email@example.com", personOrm, personaOrm);
//        final PersonaEmailPasswordAuthenticatedToken authenticatedToken = new PersonaEmailPasswordAuthenticatedToken(personaDetails);
////        final PersonaEmailPasswordAuthenticatedToken authenticatedToken = mock(PersonaEmailPasswordAuthenticatedToken.class);
//		when(personaEmailPasswordAuthenticationProvider().authenticate(any())).thenReturn(authenticatedToken);
//        // When
//		personaEmailPasswordAuthenticationProvider().authenticate(new UsernamePasswordAuthenticationToken("email@example.com", "password"));
//        // Then
//        verify(personaEmailPasswordAuthenticationProvider(), times(1)).authenticate(any());
//    }
//
//    @Test
//    void testPersonUsernameAuthenticationProvider() {
//        // Given
//        doReturn(null).when(personUsernamePasswordAuthenticationProvider()).authenticate(any()); // Adjust return value as needed
//        // When
//        personUsernamePasswordAuthenticationProvider().authenticate(new UsernamePasswordAuthenticationToken("user", "password"));
//        // Then
//        verify(personUsernamePasswordAuthenticationProvider(), times(1)).authenticate(any());
//    }
}
