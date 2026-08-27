package ru.alar.authgateway.adapters.inbound.auth;

import org.junit.jupiter.api.Test;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.server.WebFilterExchange;
import ru.alar.authgateway.bootstrap.config.AuthGatewayProperties;
import ru.alar.authgateway.bootstrap.config.AuthMetrics;
import reactor.core.publisher.Mono;

import java.net.URI;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

class LoginFailureHandlerTests {

    @Test
    void invalidatesAnonymousLoginSessionAndRedirectsToFixedFailureUri() {
        AuthGatewayProperties properties = mock(AuthGatewayProperties.class);
        AuthMetrics metrics = mock(AuthMetrics.class);
        when(properties.loginFailureUri()).thenReturn(URI.create("https://frontend.example/auth/error"));
        var handler = new LoginFailureHandler(metrics, properties);
        var exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/login/oauth2/code/zitadel"));
        var session = exchange.getSession().block();
        session.getAttributes().put("login-attempt", "value");

        handler.onAuthenticationFailure(
                        new WebFilterExchange(exchange, _ -> Mono.empty()),
                        mock(AuthenticationException.class))
                .block();

        assertThat(session.isStarted()).isFalse();
        assertThat(exchange.getResponse().getHeaders().getLocation())
                .isEqualTo(URI.create("https://frontend.example/auth/error"));
        verify(metrics).loginFailed();
    }

    @Test
    void preservesExistingAuthenticatedSessionOnFailedRepeatedCallback() {
        AuthGatewayProperties properties = mock(AuthGatewayProperties.class);
        AuthMetrics metrics = mock(AuthMetrics.class);
        when(properties.loginFailureUri()).thenReturn(URI.create("https://frontend.example/auth/error"));
        var handler = new LoginFailureHandler(metrics, properties);
        var base = MockServerWebExchange.from(MockServerHttpRequest.get("/login/oauth2/code/zitadel"));
        var session = base.getSession().block();
        session.getAttributes().put("authenticated", true);
        var exchange = base.mutate()
                .principal(Mono.just(new TestingAuthenticationToken("subject", "credentials")))
                .build();

        handler.onAuthenticationFailure(
                        new WebFilterExchange(exchange, _ -> Mono.empty()),
                        mock(AuthenticationException.class))
                .block();

        assertThat(session.<Boolean>getAttribute("authenticated")).isTrue();
    }
}
