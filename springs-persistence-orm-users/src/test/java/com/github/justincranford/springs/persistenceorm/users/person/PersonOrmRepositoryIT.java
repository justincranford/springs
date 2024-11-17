package com.github.justincranford.springs.persistenceorm.users.person;

import com.github.justincranford.springs.persistenceorm.users.AbstractIT;
import jakarta.transaction.Transactional;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.stream.Stream;

// TODO
@Slf4j
@SuppressWarnings({ "unused" })
public class PersonOrmRepositoryIT extends AbstractIT {
    public static Stream<Args> args() {
        return Stream.of(
            new Args(0),
            new Args(1),
            new Args(3)
        );
    }

    @Transactional
    @ParameterizedTest
    @MethodSource("args")
    public void createRead(final Args args) {
        // empty
    }

    public record Args(int numPersons) { }
}
