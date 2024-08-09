package com.github.justincranford.springs.persistenceorm.base.properties;

import java.time.Duration;
import java.time.temporal.ChronoUnit;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.convert.DataSizeUnit;
import org.springframework.boot.convert.DurationUnit;
import org.springframework.context.annotation.PropertySource;
import org.springframework.stereotype.Component;
import org.springframework.util.unit.DataSize;
import org.springframework.util.unit.DataUnit;

import jakarta.annotation.Nonnull;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern.Flag;
import jakarta.validation.constraints.Positive;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;

@Component
@ConfigurationProperties(prefix="mail",ignoreUnknownFields=false,ignoreInvalidFields=false)
@PropertySource("classpath:springs-persistence-orm-base.properties")
@Valid
@Getter
@Setter
@ToString(callSuper=false)
@Builder(toBuilder=true)
@NoArgsConstructor
@AllArgsConstructor
public class SpringsPersistenceOrmBaseProperties {
	@Nonnull
	@NotNull
	@NotBlank
	@Size(min=1, max=255)
    private String hostName;

	@Nonnull
	@Min(value=1)
	@Max(value=65535)
	@Positive
    private Integer port;

	@Nonnull
	@NotNull
	@NotBlank
	@Size(min=1+1+1, max=64+1+255)
	@Email(flags = { Flag.CASE_INSENSITIVE })
    private String from;

	@Nonnull
	@NotNull
//	@PositiveOrZero
    @DurationUnit(ChronoUnit.DAYS)
    private Duration durationInDays;

	@Nonnull
	@NotNull
//	@Min(value = 0)
//	@PositiveOrZero
    @DataSizeUnit(DataUnit.TERABYTES)
    private DataSize sizeInTB;
}
