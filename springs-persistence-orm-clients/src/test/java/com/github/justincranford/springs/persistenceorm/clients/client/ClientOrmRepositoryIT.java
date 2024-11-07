package com.github.justincranford.springs.persistenceorm.clients.client;

import java.util.stream.Stream;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import com.github.justincranford.springs.persistenceorm.clients.AbstractIT;

import jakarta.transaction.Transactional;
import lombok.extern.slf4j.Slf4j;

//TODO
@Slf4j
@SuppressWarnings({"unused"})
public class ClientOrmRepositoryIT extends AbstractIT {
	public record Args(int numClients) {}
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
