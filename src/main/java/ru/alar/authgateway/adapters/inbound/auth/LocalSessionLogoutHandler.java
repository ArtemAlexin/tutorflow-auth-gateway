package ru.alar.authgateway.adapters.inbound.auth;

import org.springframework.security.core.Authentication;
import org.springframework.security.web.server.WebFilterExchange;
import org.springframework.security.web.server.authentication.logout.ServerLogoutHandler;
import org.springframework.web.server.WebSession;
import reactor.core.publisher.Mono;
import ru.alar.authgateway.bootstrap.config.AuthMetrics;

public final class LocalSessionLogoutHandler implements ServerLogoutHandler {
    private final AuthMetrics metrics;

    public LocalSessionLogoutHandler(AuthMetrics metrics) {
        this.metrics = metrics;
    }

    @Override
    public Mono<Void> logout(WebFilterExchange web, Authentication authentication) {
        return web.getExchange()
                .getSession()
                .flatMap(WebSession::invalidate)
                .doOnSuccess(_ -> metrics.logoutSucceeded());
    }
}
