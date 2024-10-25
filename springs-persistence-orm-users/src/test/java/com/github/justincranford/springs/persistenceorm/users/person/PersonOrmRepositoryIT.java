package com.github.justincranford.springs.persistenceorm.users.person;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.stream.IntStream;
import java.util.stream.Stream;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import com.github.justincranford.springs.persistenceorm.users.AbstractIT;
import com.github.justincranford.springs.persistenceorm.users.person.PersonOrm;
import com.github.justincranford.springs.util.basic.SecureRandomUtil;
import com.github.justincranford.springs.util.basic.StringUtil;

import jakarta.transaction.Transactional;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@SuppressWarnings("nls")
public class PersonOrmRepositoryIT extends AbstractIT {
	public record Args(int numApples) {}
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
