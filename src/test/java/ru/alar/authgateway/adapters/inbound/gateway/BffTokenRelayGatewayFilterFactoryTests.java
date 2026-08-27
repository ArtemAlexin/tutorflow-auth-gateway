package ru.alar.authgateway.adapters.inbound.gateway;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.time.Instant;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class BffTokenRelayGatewayFilterFactoryTests {

    @Test
    void relaysSessionAuthorizedClientAndRemovesBrowserCredentials() {
        ReactiveOAuth2AuthorizedClientManager manager = mock(ReactiveOAuth2AuthorizedClientManager.class);
        when(manager.authorize(any(OAuth2AuthorizeRequest.class))).thenReturn(Mono.just(authorizedClient()));
        var factory = new BffTokenRelayGatewayFilterFactory(manager, "zitadel");
        var exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/api/test")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer client-supplied")
                        .header(HttpHeaders.COOKIE, "SESSION=id")
                        .header(HttpHeaders.PROXY_AUTHORIZATION, "Basic credentials"))
                .mutate()
                .principal(Mono.just(new TestingAuthenticationToken("subject", "credentials")))
                .build();
        var forwarded = new AtomicReference<org.springframework.web.server.ServerWebExchange>();

        StepVerifier.create(factory.apply(new BffTokenRelayGatewayFilterFactory.Config())
                        .filter(exchange, filtered -> {
                            forwarded.set(filtered);
                            return Mono.empty();
                        }))
                .verifyComplete();

        HttpHeaders headers = forwarded.get().getRequest().getHeaders();
        assertThat(headers.getFirst(HttpHeaders.AUTHORIZATION)).isEqualTo("Bearer access");
        assertThat(headers.get(HttpHeaders.COOKIE)).isNull();
        assertThat(headers.get(HttpHeaders.PROXY_AUTHORIZATION)).isNull();
        assertThat(exchange.getResponse().getStatusCode()).isNull();
    }

    @Test
    void invalidatesPartialSessionWhenAuthorizedClientIsMissing() {
        ReactiveOAuth2AuthorizedClientManager manager = mock(ReactiveOAuth2AuthorizedClientManager.class);
        when(manager.authorize(any(OAuth2AuthorizeRequest.class))).thenReturn(Mono.empty());
        var factory = new BffTokenRelayGatewayFilterFactory(manager, "zitadel");
        var exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/api/test"))
                .mutate()
                .principal(Mono.just(new TestingAuthenticationToken("subject", "credentials")))
                .build();
        var session = exchange.getSession().block();
        session.getAttributes().put("partial", true);

        StepVerifier.create(factory.apply(new BffTokenRelayGatewayFilterFactory.Config())
                        .filter(exchange, _ -> Mono.empty()))
                .verifyComplete();

        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(org.springframework.http.HttpStatus.UNAUTHORIZED);
        assertThat(session.isStarted()).isFalse();
    }

    @Test
    void invalidatesSessionWhenManagerCannotRefreshExpiredAccessToken() {
        ReactiveOAuth2AuthorizedClientManager manager = mock(ReactiveOAuth2AuthorizedClientManager.class);
        when(manager.authorize(any(OAuth2AuthorizeRequest.class)))
                .thenReturn(Mono.just(authorizedClient(Instant.parse("2020-01-01T00:00:00Z"))));
        var factory = new BffTokenRelayGatewayFilterFactory(manager, "zitadel");
        var exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/api/test"))
                .mutate()
                .principal(Mono.just(new TestingAuthenticationToken("subject", "credentials")))
                .build();
        var session = exchange.getSession().block();
        session.getAttributes().put("authenticated", true);

        StepVerifier.create(factory.apply(new BffTokenRelayGatewayFilterFactory.Config())
                        .filter(exchange, _ -> Mono.empty()))
                .verifyComplete();

        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(org.springframework.http.HttpStatus.UNAUTHORIZED);
        assertThat(session.isStarted()).isFalse();
    }

    private static OAuth2AuthorizedClient authorizedClient() {
        return authorizedClient(Instant.now().plusSeconds(300));
    }

    private static OAuth2AuthorizedClient authorizedClient(Instant expiresAt) {
        var registration = ClientRegistration.withRegistrationId("zitadel")
                .clientId("client")
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri("https://gateway/login/oauth2/code/zitadel")
                .authorizationUri("https://issuer/authorize")
                .tokenUri("https://issuer/token")
                .build();
        Instant now = expiresAt.minusSeconds(300);
        var access = new OAuth2AccessToken(
                OAuth2AccessToken.TokenType.BEARER,
                "access",
                now,
                expiresAt);
        return new OAuth2AuthorizedClient(registration, "subject", access);
    }
}
