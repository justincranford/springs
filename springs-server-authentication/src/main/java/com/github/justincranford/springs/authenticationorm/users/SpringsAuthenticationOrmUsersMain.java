package com.github.justincranford.springs.authenticationorm.users;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Import;

import com.github.justincranford.springs.authenticationorm.users.config.SpringsAuthenticationOrmUsersConfiguration;
import com.github.justincranford.springs.util.https.server.initializer.TlsEnabledByDefaultInitializer;

@SpringBootApplication
@Import({SpringsAuthenticationOrmUsersConfiguration.class})
@SuppressWarnings({"resource"})
public class SpringsAuthenticationOrmUsersMain {
	public static void main(final String[] args) {
		final SpringApplication springApplication = new SpringApplication(SpringsAuthenticationOrmUsersMain.class);
		springApplication.addInitializers(new TlsEnabledByDefaultInitializer());
		springApplication.run(args);
	}
}
