package ru.alar.authgateway.bootstrap.config;

import io.netty.channel.ChannelOption;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientProviderBuilder;
import org.springframework.security.oauth2.client.endpoint.OAuth2RefreshTokenGrantRequest;
import org.springframework.security.oauth2.client.endpoint.ReactiveOAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.WebClientReactiveRefreshTokenTokenResponseClient;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultReactiveOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.server.WebSessionServerOAuth2AuthorizedClientRepository;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.netty.http.client.HttpClient;
import ru.alar.authgateway.adapters.inbound.auth.LoginFailureHandler;
import ru.alar.authgateway.adapters.inbound.auth.LoginSuccessHandler;
import ru.alar.authgateway.adapters.inbound.auth.LocalSessionLogoutHandler;
import ru.alar.authgateway.adapters.inbound.gateway.BffTokenRelayGatewayFilterFactory;

@Configuration(proxyBeanMethods = false)
public class ApplicationConfiguration {

    @Bean
    ServerOAuth2AuthorizedClientRepository authorizedClientRepository() {
        return new WebSessionServerOAuth2AuthorizedClientRepository();
    }

    @Bean
    ReactiveOAuth2AccessTokenResponseClient<OAuth2RefreshTokenGrantRequest> refreshTokenResponseClient(
            AuthGatewayProperties properties,
            AuthMetrics metrics) {
        int connectTimeout = Math.toIntExact(properties.token().connectTimeout().toMillis());
        HttpClient http = HttpClient.create()
                .option(ChannelOption.CONNECT_TIMEOUT_MILLIS, connectTimeout)
                .responseTimeout(properties.token().responseTimeout());
        var result = new WebClientReactiveRefreshTokenTokenResponseClient();
        result.setWebClient(WebClient.builder()
                .clientConnector(new ReactorClientHttpConnector(http))
                .build());
        return request -> result.getTokenResponse(request)
                .doOnSuccess(_ -> metrics.refreshSucceeded())
                .doOnError(_ -> metrics.refreshFailed());
    }

    @Bean
    ReactiveOAuth2AuthorizedClientManager authorizedClientManager(
            ReactiveClientRegistrationRepository registrations,
            ServerOAuth2AuthorizedClientRepository authorizedClients,
            ReactiveOAuth2AccessTokenResponseClient<OAuth2RefreshTokenGrantRequest> refreshClient,
            AuthGatewayProperties properties) {
        var provider = ReactiveOAuth2AuthorizedClientProviderBuilder.builder()
                .refreshToken(refresh -> refresh
                        .accessTokenResponseClient(refreshClient)
                        .clockSkew(properties.token().refreshAhead()))
                .build();
        var manager = new DefaultReactiveOAuth2AuthorizedClientManager(registrations, authorizedClients);
        manager.setAuthorizedClientProvider(provider);
        return manager;
    }

    @Bean
    LoginSuccessHandler loginSuccessHandler(
            AuthGatewayProperties properties,
            AuthMetrics metrics) {
        return new LoginSuccessHandler(properties, metrics);
    }

    @Bean
    LoginFailureHandler loginFailureHandler(
            AuthMetrics metrics,
            AuthGatewayProperties properties) {
        return new LoginFailureHandler(metrics, properties);
    }

    @Bean
    LocalSessionLogoutHandler localSessionLogoutHandler(AuthMetrics metrics) {
        return new LocalSessionLogoutHandler(metrics);
    }

    @Bean
    BffTokenRelayGatewayFilterFactory bffTokenRelayGatewayFilterFactory(
            ReactiveOAuth2AuthorizedClientManager authorizedClients,
            AuthGatewayProperties properties) {
        return new BffTokenRelayGatewayFilterFactory(authorizedClients, properties.registrationId());
    }
}
