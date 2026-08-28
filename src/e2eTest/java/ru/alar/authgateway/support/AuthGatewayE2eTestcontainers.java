package ru.alar.authgateway.support;

import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.utility.DockerImageName;
import org.testcontainers.utility.MountableFile;

import java.net.URI;

public final class AuthGatewayE2eTestcontainers {
    private static final Object REDIS_MONITOR = new Object();
    private static final Object OIDC_MONITOR = new Object();

    @SuppressWarnings("resource")
    private static final GenericContainer<?> REDIS = new GenericContainer<>(
            DockerImageName.parse("redis:7.4-alpine"))
            .withExposedPorts(6379);

    @SuppressWarnings("resource")
    private static final GenericContainer<?> OIDC = new GenericContainer<>(
            DockerImageName.parse("ghcr.io/navikt/mock-oauth2-server:3.0.3"))
            .withCopyFileToContainer(
                    MountableFile.forClasspathResource("oidc/config.json"),
                    "/app/config.json")
            .withEnv("JSON_CONFIG_PATH", "/app/config.json")
            .withExposedPorts(8080)
            .waitingFor(Wait.forHttp("/isalive"));

    private AuthGatewayE2eTestcontainers() {
    }

    public static GenericContainer<?> redis() {
        synchronized (REDIS_MONITOR) {
            if (!REDIS.isRunning()) {
                REDIS.start();
            }
            return REDIS;
        }
    }

    public static GenericContainer<?> oidc() {
        synchronized (OIDC_MONITOR) {
            if (!OIDC.isRunning()) {
                OIDC.start();
            }
            return OIDC;
        }
    }

    public static URI oidcBaseUri() {
        GenericContainer<?> oidc = oidc();
        return URI.create("http://127.0.0.1:" + oidc.getMappedPort(8080));
    }
}
