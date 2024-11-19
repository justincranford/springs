package com.github.justincranford.springs.persistenceorm.clients.properties;
import java.util.ArrayList;
import java.util.List;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.PropertySource;
import org.springframework.lang.Nullable;
import org.springframework.stereotype.Component;
import org.springframework.validation.annotation.Validated;

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

//Caused by: org.springframework.boot.context.properties.bind.BindException: Failed to bind properties under
// 'springs.persistenceorm.clients' to com.github.justincranford.springs.persistenceorm.clients.properties.SpringsPersistenceOrmClientsClientProperties
//Caused by: org.springframework.boot.context.properties.bind.validation.BindValidationException:
// Binding validation errors on springs.persistenceorm.clients.client[0]

@Component
@ConfigurationProperties(prefix="springs.persistenceorm.clients", ignoreUnknownFields=false, ignoreInvalidFields=false)
@PropertySource("classpath:springs-persistence-orm-clients.properties")
@Validated
@Getter
@Setter
@ToString
@Builder(toBuilder=true)
@NoArgsConstructor
@AllArgsConstructor
public class SpringsPersistenceOrmClientsClientProperties {
    @NotNull
    @NotEmpty
    @Builder.Default
    private List<SpringsPersistenceOrmClientsClientProperties.Client> client = new ArrayList<>();

    public List<SpringsPersistenceOrmClientsClientProperties.Client> getClient() {
        return this.client;
    }

    public void setClient(List<SpringsPersistenceOrmClientsClientProperties.Client> _clients) {
        this.client = _clients;
    }

    @Validated
    @Getter
    @Setter
    @ToString
    public static class Client {
    	@NotEmpty
        private String clientName;
    	@Nullable
        private String secret;
    	@NotNull
        private ClientStatusType clientStatus;
    	@NotNull
        private ClientType clientType;
        @NotNull
        private List<String> clientTimeZones = new ArrayList<>(1);
    }
}
