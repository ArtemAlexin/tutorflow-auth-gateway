package ru.alar.authgateway.adapters.inbound.gateway;

import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.time.Instant;

public final class BffTokenRelayGatewayFilterFactory
        extends AbstractGatewayFilterFactory<BffTokenRelayGatewayFilterFactory.Config> {
    private final ReactiveOAuth2AuthorizedClientManager authorizedClients;
    private final String registrationId;

    public BffTokenRelayGatewayFilterFactory(
            ReactiveOAuth2AuthorizedClientManager authorizedClients,
            String registrationId) {
        super(Config.class);
        this.authorizedClients = authorizedClients;
        this.registrationId = registrationId;
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> resolveAuthorizedClient(exchange)
                .switchIfEmpty(Mono.error(new ReauthenticationRequiredException()))
                .flatMap(client -> {
                    var request = exchange.getRequest()
                            .mutate()
                            .headers(headers -> {
                                headers.remove(HttpHeaders.AUTHORIZATION);
                                headers.remove(HttpHeaders.COOKIE);
                                headers.remove(HttpHeaders.PROXY_AUTHORIZATION);
                                headers.setBearerAuth(client.getAccessToken().getTokenValue());
                            })
                            .build();
                    return chain.filter(exchange.mutate()
                            .request(request)
                            .build());
                })
                .onErrorResume(ReauthenticationRequiredException.class,
                        _ -> invalidateAndComplete(exchange, HttpStatus.UNAUTHORIZED))
                .onErrorResume(AuthorizedClientUnavailableException.class,
                        _ -> complete(exchange, HttpStatus.SERVICE_UNAVAILABLE));
    }

    private Mono<OAuth2AuthorizedClient> resolveAuthorizedClient(ServerWebExchange exchange) {
        return exchange.getPrincipal()
                .filter(Authentication.class::isInstance)
                .cast(Authentication.class)
                .flatMap(authentication -> authorizedClients.authorize(
                        OAuth2AuthorizeRequest.withClientRegistrationId(registrationId)
                                .principal(authentication)
                                .attribute(ServerWebExchange.class.getName(), exchange)
                                .build()))
                .filter(this::hasUsableAccessToken)
                .onErrorMap(OAuth2AuthorizationException.class, error ->
                        "invalid_grant".equals(error.getError().getErrorCode())
                                ? new ReauthenticationRequiredException(error)
                                : new AuthorizedClientUnavailableException(error))
                .onErrorMap(error -> !(error instanceof ReauthenticationRequiredException)
                                && !(error instanceof AuthorizedClientUnavailableException),
                        AuthorizedClientUnavailableException::new);
    }

    private boolean hasUsableAccessToken(OAuth2AuthorizedClient client) {
        Instant expiresAt = client.getAccessToken().getExpiresAt();
        return expiresAt != null && expiresAt.isAfter(Instant.now());
    }

    private static Mono<Void> invalidateAndComplete(ServerWebExchange exchange, HttpStatus status) {
        return exchange.getSession()
                .flatMap(session -> session.invalidate().onErrorResume(_ -> Mono.empty()))
                .then(complete(exchange, status));
    }

    private static Mono<Void> complete(ServerWebExchange exchange, HttpStatus status) {
        return Mono.defer(() -> {
            exchange.getResponse().setStatusCode(status);
            exchange.getResponse().getHeaders().setContentLength(0);
            return exchange.getResponse().setComplete();
        });
    }

    public static final class Config {
    }

    private static final class ReauthenticationRequiredException extends RuntimeException {
        private ReauthenticationRequiredException() {
        }

        private ReauthenticationRequiredException(Throwable cause) {
            super(cause);
        }
    }

    private static final class AuthorizedClientUnavailableException extends RuntimeException {
        private AuthorizedClientUnavailableException(Throwable cause) {
            super(cause);
        }
    }
}
