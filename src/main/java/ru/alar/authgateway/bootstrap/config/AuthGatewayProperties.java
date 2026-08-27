package ru.alar.authgateway.bootstrap.config;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import java.net.URI;
import java.time.Duration;

@Validated
@ConfigurationProperties(prefix = "tutorflow.auth")
public record AuthGatewayProperties(
        @NotBlank String registrationId,
        @NotNull URI frontendOrigin,
        @NotNull URI loginSuccessUri,
        @NotNull URI loginFailureUri,
        @Valid @NotNull Token token,
        @Valid @NotNull Zitadel zitadel
) {
    public record Token(
            @NotNull Duration refreshAhead,
            @NotNull Duration connectTimeout,
            @NotNull Duration responseTimeout
    ) {
    }

    public record Zitadel(
            @NotNull URI issuerUri,
            @NotNull URI authorizationUri,
            @NotNull URI tokenUri,
            @NotNull URI jwkSetUri,
            @NotNull URI userInfoUri,
            @NotBlank String clientId,
            @NotBlank String organizationId,
            @NotBlank String tutorflowProjectId
    ) {
    }
}
