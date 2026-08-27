package ru.alar.authgateway.adapters.inbound.auth;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.test.web.reactive.server.WebTestClient;
import ru.alar.authgateway.support.RedisIntegrationTest;

import static org.assertj.core.api.Assertions.assertThat;

class OAuthAuthorizationIntegrationTests extends RedisIntegrationTest {
    @Autowired
    ApplicationContext context;

    @Test
    void authorizationRedirectUsesPkceAndCreatesOnlySessionCookie() {
        WebTestClient.bindToApplicationContext(context)
                .configureClient()
                .build()
                .get()
                .uri("/oauth2/authorization/zitadel")
                .exchange()
                .expectStatus()
                .is3xxRedirection()
                .expectCookie()
                .exists("TUTORFLOW_SESSION")
                .expectHeader()
                .value("Location", location -> assertThat(location)
                        .contains("code_challenge=")
                        .contains("code_challenge_method=S256")
                        .contains("prompt=select_account")
                        .contains("client_id=tutorflow-local-development-client"));
    }

    @Test
    void invalidCallbackRedirectsToFixedFrontendFailureUri() {
        WebTestClient.bindToApplicationContext(context)
                .configureClient()
                .build()
                .get()
                .uri("/login/oauth2/code/zitadel?code=invalid&state=invalid")
                .exchange()
                .expectStatus()
                .is3xxRedirection()
                .expectHeader()
                .valueEquals("Location", "http://localhost:5173/auth/error");
    }
}
