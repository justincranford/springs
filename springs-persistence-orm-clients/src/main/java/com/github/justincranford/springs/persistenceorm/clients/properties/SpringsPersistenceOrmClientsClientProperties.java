package com.github.justincranford.springs.persistenceorm.clients.properties;

import com.github.justincranford.springs.persistenceorm.clients.client.enums.ClientStatusType;
import com.github.justincranford.springs.persistenceorm.clients.client.enums.ClientType;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.PropertySource;
import org.springframework.lang.Nullable;
import org.springframework.stereotype.Component;
import org.springframework.validation.annotation.Validated;

import java.util.ArrayList;
import java.util.List;

@Component
@ConfigurationProperties(prefix = "springs.persistenceorm.clients", ignoreUnknownFields = false)
@PropertySource("classpath:springs-persistence-orm-clients.properties")
@Validated
@Getter
@Setter
@ToString
@Builder(toBuilder = true)
@NoArgsConstructor
@AllArgsConstructor
public class SpringsPersistenceOrmClientsClientProperties {
    @NotNull
    @NotEmpty
    @Builder.Default
    private List<SpringsPersistenceOrmClientsClientProperties.Client> clients = new ArrayList<>();

    @Validated
    @Getter
    @Setter
    @ToString
    public static class Client {
        @NotEmpty
        private String clientId;
        @Nullable
        private String password;
        @NotNull
        private ClientStatusType status;
        @NotNull
        private ClientType type;
        private List<String> timezones = new ArrayList<>();
    }
}
