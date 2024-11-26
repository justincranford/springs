package com.github.justincranford.springs.persistenceredis.sessions.generator;

import com.github.justincranford.springs.persistenceorm.base.entity.BytesIdGenerator;
import com.github.justincranford.springs.util.basic.Base64Util;
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import org.jetbrains.annotations.NotNull;
import org.springframework.session.SessionIdGenerator;

@NoArgsConstructor(access=AccessLevel.PUBLIC)
public final class CustomSessionIdGenerator implements SessionIdGenerator {
    private static final BytesIdGenerator SESSION_ID_GENERATOR = new BytesIdGenerator("sessionId");

    @SuppressFBWarnings(value="NP_NONNULL_RETURN_VIOLATION",justification="False positive")
    public @NotNull String generate() {
        return Base64Util.URL.encodeToString(SESSION_ID_GENERATOR.generate());
    }
}
