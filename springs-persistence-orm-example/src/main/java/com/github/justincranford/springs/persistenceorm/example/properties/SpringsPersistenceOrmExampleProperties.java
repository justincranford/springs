package com.github.justincranford.springs.persistenceorm.example.properties;

import java.time.Duration;
import java.time.temporal.ChronoUnit;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.convert.DataSizeUnit;
import org.springframework.boot.convert.DurationUnit;
import org.springframework.context.annotation.PropertySource;
import org.springframework.stereotype.Component;
import org.springframework.util.unit.DataSize;
import org.springframework.util.unit.DataUnit;
import org.springframework.validation.annotation.Validated;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotEmpty;
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
@ConfigurationProperties(prefix="springs.persistenceorm.example",ignoreUnknownFields=false,ignoreInvalidFields=false)
@PropertySource("classpath:springs-persistence-orm-example.properties")
@Validated
@Getter
@Setter
@ToString(callSuper=false)
@Builder(toBuilder=true)
@NoArgsConstructor
@AllArgsConstructor
public class SpringsPersistenceOrmExampleProperties {
	@NotNull
	@NotEmpty
	@Size(min=1, max=255)
    private String hostName;

	@NotNull
	@Min(value=1)
	@Max(value=65535)
	@Positive
    private Integer port;

	@NotNull
	@NotEmpty
	@Size(min=1+1+1, max=64+1+255)
	@Email(flags = { Flag.CASE_INSENSITIVE })
    private String from;

	@NotNull
//	@PositiveOrZero
    @DurationUnit(ChronoUnit.DAYS)
    private Duration durationInDays;

	@NotNull
//	@Min(value = 0)
//	@PositiveOrZero
    @DataSizeUnit(DataUnit.TERABYTES)
    private DataSize sizeInTB;
}
