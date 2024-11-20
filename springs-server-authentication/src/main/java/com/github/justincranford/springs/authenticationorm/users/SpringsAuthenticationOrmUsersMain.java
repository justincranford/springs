package com.github.justincranford.springs.authenticationorm.users;

import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Import;

import com.github.justincranford.springs.authenticationorm.users.config.SpringsAuthenticationOrmUsersConfiguration;
import com.github.justincranford.springs.util.https.server.bootstrap.TlsEnabledByDefaultApplicationContextInitializer;

@SpringBootApplication
@Import({SpringsAuthenticationOrmUsersConfiguration.class})
@NoArgsConstructor(access=AccessLevel.PRIVATE)
public final class SpringsAuthenticationOrmUsersMain {
	public static void main(final String[] args) {
		final SpringApplication springApplication = new SpringApplication(SpringsAuthenticationOrmUsersMain.class);
		springApplication.addInitializers(new TlsEnabledByDefaultApplicationContextInitializer());
		springApplication.run(args);
	}
}
