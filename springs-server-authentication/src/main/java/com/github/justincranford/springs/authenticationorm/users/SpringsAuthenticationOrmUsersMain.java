package com.github.justincranford.springs.authenticationorm.users;

import com.github.justincranford.springs.authenticationorm.users.config.SpringsAuthenticationOrmUsersConfiguration;
import com.github.justincranford.springs.util.https.server.initializer.TlsEnabledByDefaultInitializer;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Import;

@SpringBootApplication
@Import({ SpringsAuthenticationOrmUsersConfiguration.class })
public class SpringsAuthenticationOrmUsersMain {
    public static void main(final String[] args) {
        final SpringApplication springApplication = new SpringApplication(SpringsAuthenticationOrmUsersMain.class);
        springApplication.addInitializers(new TlsEnabledByDefaultInitializer());
        springApplication.run(args);
    }
}
