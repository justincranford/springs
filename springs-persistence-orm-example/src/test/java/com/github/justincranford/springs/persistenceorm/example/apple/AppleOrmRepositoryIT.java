package com.github.justincranford.springs.persistenceorm.example.apple;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.stream.IntStream;
import java.util.stream.Stream;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import com.github.justincranford.springs.persistenceorm.example.AbstractIT;
import com.github.justincranford.springs.persistenceorm.example.apple.AppleOrm.Type;
import com.github.justincranford.springs.util.basic.SecureRandomUtil;
import com.github.justincranford.springs.util.basic.StringUtil;

import jakarta.transaction.Transactional;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@SuppressWarnings("nls")
public class AppleOrmRepositoryIT extends AbstractIT {
	private static final int appleOffsetStart = 1000000;
	private static final String description = "description";

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
		System.out.println("============================================================");
		log.info("args: {}", args);
		IntStream.range(appleOffsetStart, appleOffsetStart + args.numApples()).forEach(appleOffset -> {
			final Type type = SecureRandomUtil.staticRandomEnumElement(AppleOrm.Type.class);
			final AppleOrm savedApple = super.appleOrmRepository().save(AppleOrm.builder().type(type).description(description + "_" + appleOffset).build());
			final Optional<AppleOrm> appleById = super.appleOrmRepository().findById(savedApple.internalId());
			assertThat(appleById).isPresent();
			log.info("Apple By ID: {}\n{}\n", savedApple.internalId(), appleById.orElseThrow());
		});
		IntStream.range(appleOffsetStart, appleOffsetStart + args.numApples()).forEach(appleOffset -> {
			final Type type = SecureRandomUtil.staticRandomEnumElement(AppleOrm.Type.class);
			final AppleOrm savedApple = super.appleOrmRepository().save(AppleOrm.builder().type(type).description("").build());
			final Optional<AppleOrm> appleById = super.appleOrmRepository().findById(savedApple.internalId());
			assertThat(appleById).isPresent();
			log.info("Apple By ID: {}\n{}\n", savedApple.internalId(), appleById.orElseThrow());
		});
		final List<AppleOrm> applesAll = super.appleOrmRepository().findAll();
		assertThat(applesAll).isNotNull().hasSize(args.numApples() * 2);
		log.info("Apples All:\n{}\n", StringUtil.toString("", "\n", "", applesAll));

		Arrays.stream(AppleOrm.Type.values()).forEach(type -> {
			final List<AppleOrm> applesByType = super.appleOrmRepository().findByType(type);
			assertThat(applesAll).isNotNull().hasSizeLessThanOrEqualTo(args.numApples() * 2);
			log.info("Apples By Type: {}\n{}\n", type, StringUtil.toString("", "\n", "", applesByType));
		});

		final List<AppleOrm> applesByDescription = super.appleOrmRepository().findByDescription(description);
		assertThat(applesByDescription).isNotNull().isEmpty();
		log.info("Apples By Description: {}\n{}\n", description, StringUtil.toString("", "\n", "", applesByDescription));

		Arrays.stream(AppleOrm.Type.values()).forEach(type -> {
			final List<AppleOrm> applesByTypeAndDescription = super.appleOrmRepository().findByTypeAndDescription(type, description);
			assertThat(applesByTypeAndDescription).isNotNull().isEmpty();
			log.info("Apples By Type {}, Description: {}\n{}\n", type, description, StringUtil.toString("", "\n", "", applesByTypeAndDescription));
		});

		final List<AppleOrm> applesByDescriptionStartsWith = super.appleOrmRepository().findByDescriptionStartsWith(description);
		assertThat(applesByDescriptionStartsWith).isNotNull().hasSize(args.numApples());
		log.info("Apples By Description Starts With: {}\n{}\n", description, StringUtil.toString("", "\n", "", applesByDescriptionStartsWith));

		Arrays.stream(AppleOrm.Type.values()).forEach(type -> {
			final List<AppleOrm> applesByTypeAndDescriptionStartsWith = super.appleOrmRepository().findByTypeAndDescriptionStartsWith(type, description);
			assertThat(applesByTypeAndDescriptionStartsWith).isNotNull().hasSizeLessThanOrEqualTo(args.numApples());
			log.info("Apples By Type: {}, Description Starts With: {}\n{}\n", type, description, StringUtil.toString("", "\n", "", applesByTypeAndDescriptionStartsWith));
		});

		final List<AppleOrm> applesByDescriptionContaining = super.appleOrmRepository().findByDescriptionContaining(description);
		assertThat(applesByDescriptionContaining).isNotNull().hasSize(args.numApples());
		log.info("Apples By Description Containing: {}\n{}\n", description, StringUtil.toString("", "\n", "", applesByDescriptionContaining));

		Arrays.stream(AppleOrm.Type.values()).forEach(type -> {
			final List<AppleOrm> applesByTypeAndDescriptionContaining = super.appleOrmRepository().findByTypeAndDescriptionContaining(type, description);
			assertThat(applesByTypeAndDescriptionContaining).isNotNull().hasSizeLessThanOrEqualTo(args.numApples());
			log.info("Apples By Type: {}, and Description Containing: {}\n{}\n", type, description, StringUtil.toString("", "\n", "", applesByTypeAndDescriptionContaining));
		});
		log.info("Before Delete All Apples");
		super.appleOrmRepository().deleteAll();
		log.info("After Delete All Apples");

		final List<AppleOrm> applesAllAfterDeleteAll = super.appleOrmRepository().findAll();
		assertThat(applesAllAfterDeleteAll).isNotNull().isEmpty();
		log.info("Apples All After Delete All:\n{}\n", StringUtil.toString("", "\n", "", applesAllAfterDeleteAll));
	}
}
