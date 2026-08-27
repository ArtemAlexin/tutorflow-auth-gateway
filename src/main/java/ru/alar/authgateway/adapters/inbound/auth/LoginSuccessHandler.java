package ru.alar.authgateway.adapters.inbound.auth;

import org.springframework.security.core.Authentication;
import org.springframework.security.web.server.WebFilterExchange;
import org.springframework.security.web.server.savedrequest.NoOpServerRequestCache;
import org.springframework.security.web.server.authentication.RedirectServerAuthenticationSuccessHandler;
import org.springframework.security.web.server.authentication.ServerAuthenticationSuccessHandler;
import ru.alar.authgateway.bootstrap.config.AuthGatewayProperties;
import ru.alar.authgateway.bootstrap.config.AuthMetrics;
import reactor.core.publisher.Mono;

public final class LoginSuccessHandler implements ServerAuthenticationSuccessHandler {
    private final AuthMetrics metrics;
    private final RedirectServerAuthenticationSuccessHandler redirect =
            new RedirectServerAuthenticationSuccessHandler();

    public LoginSuccessHandler(
            AuthGatewayProperties properties,
            AuthMetrics metrics) {
        this.metrics = metrics;
        redirect.setLocation(properties.loginSuccessUri());
        redirect.setRequestCache(NoOpServerRequestCache.getInstance());
    }

    @Override
    public Mono<Void> onAuthenticationSuccess(WebFilterExchange web, Authentication authentication) {
        metrics.loginSucceeded();
        return redirect.onAuthenticationSuccess(web, authentication);
    }
}
