package ru.alar.authgateway.adapters.inbound.auth;

import org.junit.jupiter.api.Test;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.server.WebFilterExchange;
import org.springframework.security.web.server.savedrequest.WebSessionServerRequestCache;
import ru.alar.authgateway.bootstrap.config.AuthGatewayProperties;
import ru.alar.authgateway.bootstrap.config.AuthMetrics;
import reactor.core.publisher.Mono;

import java.net.URI;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

class LoginSuccessHandlerTests {

    @Test
    void alwaysRedirectsToConfiguredFrontendUriIgnoringSavedRequest() {
        AuthGatewayProperties properties = mock(AuthGatewayProperties.class);
        AuthMetrics metrics = mock(AuthMetrics.class);
        Authentication authentication = mock(Authentication.class);
        when(properties.loginSuccessUri()).thenReturn(URI.create("https://frontend.example/auth/callback"));
        var handler = new LoginSuccessHandler(properties, metrics);
        var exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/api/private"));
        new WebSessionServerRequestCache().saveRequest(exchange).block();

        handler.onAuthenticationSuccess(
                        new WebFilterExchange(exchange, _ -> Mono.empty()),
                        authentication)
                .block();

        assertThat(exchange.getResponse().getHeaders().getLocation())
                .isEqualTo(URI.create("https://frontend.example/auth/callback"));
        verify(metrics).loginSucceeded();
    }
}
