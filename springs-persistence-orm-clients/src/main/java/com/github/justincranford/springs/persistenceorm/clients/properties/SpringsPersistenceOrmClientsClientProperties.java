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

@Component
@ConfigurationProperties(prefix="springs.persistenceorm.clients", ignoreUnknownFields=false, ignoreInvalidFields=false)
@PropertySource("classpath:springs-persistence-orm-clients.properties")
@Validated
@Getter
@Setter
@ToString(callSuper=false)
@Builder(toBuilder=true)
@NoArgsConstructor
@AllArgsConstructor
public class SpringsPersistenceOrmClientsClientProperties {
    @NotNull
    @NotEmpty
    @Builder.Default
    private List<SpringsPersistenceOrmClientsClientProperties.Client> clients = new ArrayList<>();

    public List<SpringsPersistenceOrmClientsClientProperties.Client> getClients() {
        return this.clients;
    }

    public void setClient(List<SpringsPersistenceOrmClientsClientProperties.Client> _clients) {
        this.clients = _clients;
    }

    @Validated
    @Getter
    @Setter
    @ToString(callSuper=false)
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
