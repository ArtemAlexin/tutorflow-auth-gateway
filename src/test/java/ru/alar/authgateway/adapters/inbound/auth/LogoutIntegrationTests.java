package ru.alar.authgateway.adapters.inbound.auth;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.session.ReactiveSessionRepository;
import org.springframework.session.Session;
import org.springframework.test.web.reactive.server.WebTestClient;
import ru.alar.authgateway.support.RedisIntegrationTest;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;

class LogoutIntegrationTests extends RedisIntegrationTest {
    @Autowired
    ApplicationContext context;
    @Autowired
    ReactiveSessionRepository<? extends Session> sessions;

    @Test
    void logoutIsIdempotentWithoutOriginHeader() {
        WebTestClient client = WebTestClient.bindToApplicationContext(context)
                .configureClient()
                .baseUrl("http://localhost")
                .build();

        client.post()
                .uri("/auth/logout")
                .exchange()
                .expectStatus()
                .isNoContent();

        client.post()
                .uri("/auth/logout")
                .exchange()
                .expectStatus()
                .isNoContent();
    }

    @Test
    void logoutInvalidatesExistingSpringSession() {
        WebTestClient client = WebTestClient.bindToApplicationContext(context)
                .configureClient()
                .baseUrl("http://localhost")
                .build();
        var authorization = client.get()
                .uri("/oauth2/authorization/zitadel")
                .exchange()
                .expectStatus()
                .is3xxRedirection()
                .expectBody()
                .returnResult();
        String sessionId = authorization.getResponseCookies()
                .getFirst("TUTORFLOW_SESSION")
                .getValue();

        client.post()
                .uri("/auth/logout")
                .cookie("TUTORFLOW_SESSION", sessionId)
                .exchange()
                .expectStatus()
                .isNoContent()
                .expectCookie()
                .maxAge("TUTORFLOW_SESSION", Duration.ZERO);

        assertThat(sessions.findById(sessionId).block()).isNull();
    }
}
