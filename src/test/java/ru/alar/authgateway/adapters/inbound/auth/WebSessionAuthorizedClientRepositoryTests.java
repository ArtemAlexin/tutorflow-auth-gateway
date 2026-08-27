package ru.alar.authgateway.adapters.inbound.auth;

import org.junit.jupiter.api.Test;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.web.server.WebSessionServerOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

class WebSessionAuthorizedClientRepositoryTests {

    @Test
    void storesLoadsAndRemovesAuthorizedClientInCurrentWebSession() {
        var repository = new WebSessionServerOAuth2AuthorizedClientRepository();
        var exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/"));
        Authentication principal = mock(Authentication.class);
        OAuth2AuthorizedClient expected = authorizedClient();

        repository.saveAuthorizedClient(expected, principal, exchange).block();

        OAuth2AuthorizedClient loaded = repository
                .loadAuthorizedClient("zitadel", principal, exchange)
                .block();
        assertThat(loaded).isSameAs(expected);

        repository.removeAuthorizedClient("zitadel", principal, exchange).block();

        assertThat(repository.loadAuthorizedClient("zitadel", principal, exchange).block()).isNull();
    }

    private static OAuth2AuthorizedClient authorizedClient() {
        var registration = ClientRegistration.withRegistrationId("zitadel")
                .clientId("client")
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri("https://gateway/login/oauth2/code/zitadel")
                .authorizationUri("https://issuer/authorize")
                .tokenUri("https://issuer/token")
                .build();
        Instant now = Instant.parse("2026-01-01T00:00:00Z");
        var access = new OAuth2AccessToken(
                OAuth2AccessToken.TokenType.BEARER,
                "access",
                now,
                now.plusSeconds(300));
        var refresh = new OAuth2RefreshToken("refresh", now);
        return new OAuth2AuthorizedClient(registration, "subject", access, refresh);
    }
}
