package ru.alar.authgateway.adapters.inbound.auth;

import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.server.WebFilterExchange;
import org.springframework.security.web.server.authentication.RedirectServerAuthenticationFailureHandler;
import org.springframework.security.web.server.authentication.ServerAuthenticationFailureHandler;
import org.springframework.web.server.WebSession;
import ru.alar.authgateway.bootstrap.config.AuthGatewayProperties;
import ru.alar.authgateway.bootstrap.config.AuthMetrics;
import reactor.core.publisher.Mono;

public final class LoginFailureHandler implements ServerAuthenticationFailureHandler {
    private final AuthMetrics metrics;
    private final RedirectServerAuthenticationFailureHandler redirect;

    public LoginFailureHandler(
            AuthMetrics metrics,
            AuthGatewayProperties properties) {
        this.metrics = metrics;
        this.redirect = new RedirectServerAuthenticationFailureHandler(
                properties.loginFailureUri().toString());
    }

    @Override
    public Mono<Void> onAuthenticationFailure(WebFilterExchange web, AuthenticationException error) {
        metrics.loginFailed();
        var exchange = web.getExchange();
        return exchange.getPrincipal()
                .hasElement()
                .flatMap(authenticated -> authenticated
                        ? Mono.empty()
                        : exchange.getSession().flatMap(WebSession::invalidate))
                .onErrorResume(_ -> Mono.empty())
                .then(redirect.onAuthenticationFailure(web, error));
    }
}
