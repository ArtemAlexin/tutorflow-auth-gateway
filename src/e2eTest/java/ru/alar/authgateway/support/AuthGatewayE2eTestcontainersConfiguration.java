package ru.alar.authgateway.support;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.test.context.DynamicPropertyRegistrar;
import org.testcontainers.containers.GenericContainer;

import java.net.URI;

@TestConfiguration(proxyBeanMethods = false)
class AuthGatewayE2eTestcontainersConfiguration {

    @Bean
    GenericContainer<?> authGatewayRedisContainer() {
        return AuthGatewayE2eTestcontainers.redis();
    }

    @Bean
    GenericContainer<?> authGatewayOidcContainer() {
        return AuthGatewayE2eTestcontainers.oidc();
    }

    @Bean
    DynamicPropertyRegistrar authGatewayE2eProperties(
            @Qualifier("authGatewayRedisContainer") GenericContainer<?> redis,
            @Qualifier("authGatewayOidcContainer") GenericContainer<?> oidc) {
        return registry -> {
            URI issuer = URI.create("http://127.0.0.1:" + oidc.getMappedPort(8080) + "/default");
            registry.add("spring.data.redis.host", redis::getHost);
            registry.add("spring.data.redis.port", () -> redis.getMappedPort(6379));
            registry.add("spring.data.redis.ssl.enabled", () -> false);
            registry.add("tutorflow.auth.zitadel.issuer-uri", issuer::toString);
            registry.add("tutorflow.auth.zitadel.authorization-uri",
                    () -> issuer.resolve("/default/authorize").toString());
            registry.add("tutorflow.auth.zitadel.jwk-set-uri",
                    () -> issuer.resolve("/default/jwks").toString());
            registry.add("tutorflow.auth.zitadel.user-info-uri",
                    () -> issuer.resolve("/default/userinfo").toString());
            registry.add("tutorflow.auth.zitadel.client-id", () -> "e2e-client");
            registry.add("tutorflow.auth.zitadel.organization-id", () -> "e2e-organization");
            registry.add("tutorflow.auth.zitadel.tutorflow-project-id", () -> "e2e-project");
        };
    }
}
