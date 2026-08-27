package ru.alar.authgateway.support;

import org.springframework.boot.test.context.SpringBootTest;
import ru.alar.authgateway.bootstrap.AuthGatewayApplication;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.utility.DockerImageName;

@SpringBootTest(classes = AuthGatewayApplication.class)
public abstract class RedisIntegrationTest {
    protected static final GenericContainer<?> REDIS = new GenericContainer<>(
            DockerImageName.parse("redis:7.4-alpine"))
            .withExposedPorts(6379);

    static {
        REDIS.start();
    }

    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry registry) {
        registry.add("spring.data.redis.host", REDIS::getHost);
        registry.add("spring.data.redis.port", () -> REDIS.getMappedPort(6379));
        registry.add("spring.data.redis.ssl.enabled", () -> false);
        registry.add("server.reactive.session.cookie.secure", () -> false);
        registry.add("server.reactive.session.cookie.name", () -> "TUTORFLOW_SESSION");
    }
}
