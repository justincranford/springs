package com.github.justincranford.springs.persistenceorm.users.person;

import java.util.stream.Stream;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import com.github.justincranford.springs.persistenceorm.users.AbstractIT;

import jakarta.transaction.Transactional;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@SuppressWarnings({"unused"})
public class PersonOrmRepositoryIT extends AbstractIT {
	public record Args(int numPersons) {}
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
}
