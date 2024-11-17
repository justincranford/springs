package com.github.justincranford.springs.persistenceorm.users.config.projection;

public interface PersonaIdAndPersonIdPasswordProjection {
    Long getPersonaId();

    Long getPersonId();

    String getPersonPassword();
}
