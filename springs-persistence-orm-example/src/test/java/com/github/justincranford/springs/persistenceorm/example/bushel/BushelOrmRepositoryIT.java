package com.github.justincranford.springs.persistenceorm.example.bushel;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import java.util.Optional;
import java.util.stream.IntStream;
import java.util.stream.Stream;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import com.github.justincranford.springs.persistenceorm.example.AbstractIT;
import com.github.justincranford.springs.persistenceorm.example.apple.AppleOrm;
import com.github.justincranford.springs.persistenceorm.example.apple.AppleOrm.Type;
import com.github.justincranford.springs.util.basic.util.SecureRandomUtil;
import com.github.justincranford.springs.util.basic.util.StringUtil;

import jakarta.transaction.Transactional;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@SuppressWarnings("nls")
public class BushelOrmRepositoryIT extends AbstractIT {
	private static final int bushelOffsetStart = 1000000;
	private static final int appleOffsetStart = 1000000;
	private static final String description = "description";

	public record Args(int numBushels, int numApples) {}
	public static Stream<Args> args() {
		return Stream.of(
			new Args(0, 0),
			new Args(1, 0),
			new Args(1, 1),
			new Args(1, 3),
			new Args(3, 0),
			new Args(3, 1),
			new Args(3, 3)
		);
	}

	@Transactional
	@ParameterizedTest
	@MethodSource("args")
	public void createRead(final Args args) {
		System.out.println("============================================================");
		log.info("args: {}", args);
		IntStream.range(bushelOffsetStart, bushelOffsetStart + args.numBushels()).forEach(bushelOffset -> {
			final BushelOrm savedBushel = super.bushelOrmRepository().save(BushelOrm.builder().build());
			final Optional<BushelOrm> bushelById = super.bushelOrmRepository().findById(savedBushel.internalId());
			assertThat(bushelById).isPresent();
			log.info("Bushel By ID: {}\n{}\n", savedBushel.internalId(), bushelById.orElseThrow());
			IntStream.range(appleOffsetStart, appleOffsetStart + args.numApples()).forEach(appleOffset -> {
				final Type type = SecureRandomUtil.staticRandomEnumElement(AppleOrm.Type.class);
				final AppleOrm savedApple = super.appleOrmRepository().save(AppleOrm.builder().type(type).description(description + "_" + appleOffset).build());
				savedBushel.addApple(savedApple);
				final Optional<AppleOrm> appleById = super.appleOrmRepository().findById(savedApple.internalId());
				assertThat(appleById).isPresent();
				log.info("Apple By ID: {}\n{}\n", savedApple.internalId(), appleById.orElseThrow());
			});
			IntStream.range(appleOffsetStart, appleOffsetStart + args.numApples()).forEach(appleOffset -> {
				final Type type = SecureRandomUtil.staticRandomEnumElement(AppleOrm.Type.class);
				final AppleOrm savedApple = super.appleOrmRepository().save(AppleOrm.builder().type(type).description("").build());
				savedBushel.addApple(savedApple);
				final Optional<AppleOrm> appleById = super.appleOrmRepository().findById(savedApple.internalId());
				assertThat(appleById).isPresent();
				log.info("Apple By ID: {}\n{}\n", savedApple.internalId(), appleById.orElseThrow());
			});
			final Optional<BushelOrm> bushelById2 = super.bushelOrmRepository().findById(savedBushel.internalId());
			assertThat(bushelById2).isPresent();
			log.info("Bushel By ID: {}\n{}\n", savedBushel.internalId(), bushelById2.orElseThrow());
		});
		final List<BushelOrm> bushelsAll = super.bushelOrmRepository().findAll();
		assertThat(bushelsAll).isNotNull().hasSize(args.numBushels());
		log.info("Bushels All:\n{}\n", StringUtil.toString("", "\n", "", bushelsAll));

		log.info("Before Delete All Apples");
		super.appleOrmRepository().deleteAll();
		log.info("After Delete All Apples");

		log.info("Before Delete All Bushels");
		super.bushelOrmRepository().deleteAll();
		log.info("After Delete All Bushels");

		log.info("Before Delete All Apples");
		super.appleOrmRepository().deleteAll();
		log.info("After Delete All Apples");

		final List<BushelOrm> bushelsAllAfterDeleteAll = super.bushelOrmRepository().findAll();
		assertThat(bushelsAllAfterDeleteAll).isNotNull().isEmpty();
		log.info("Bushels All After Delete All:\n{}\n", StringUtil.toString("", "\n", "", bushelsAllAfterDeleteAll));

		final List<AppleOrm> applesAllAfterDeleteAll = super.appleOrmRepository().findAll();
		assertThat(applesAllAfterDeleteAll).isNotNull().isEmpty();
		log.info("Apples All After Delete All:\n{}\n", StringUtil.toString("", "\n", "", applesAllAfterDeleteAll));
	}
}
