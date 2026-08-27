package ru.alar.authgateway.bootstrap.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizationRequestResolver;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.authentication.logout.HttpStatusReturningServerLogoutSuccessHandler;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsConfigurationSource;
import ru.alar.authgateway.adapters.inbound.auth.LoginFailureHandler;
import ru.alar.authgateway.adapters.inbound.auth.LoginSuccessHandler;
import ru.alar.authgateway.adapters.inbound.auth.LocalSessionLogoutHandler;

import java.util.List;

@Configuration(proxyBeanMethods = false)
@EnableWebFluxSecurity
public class SecurityConfiguration {

    @Bean
    SecurityWebFilterChain securityWebFilterChain(
            ServerHttpSecurity http,
            ServerOAuth2AuthorizedClientRepository authorizedClients,
            ServerOAuth2AuthorizationRequestResolver authorizationRequestResolver,
            LoginSuccessHandler loginSuccessHandler,
            LoginFailureHandler loginFailureHandler,
            LocalSessionLogoutHandler logoutHandler) {
        return http
                .authorizeExchange(authorize -> authorize
                        .pathMatchers(HttpMethod.OPTIONS).permitAll()
                        .pathMatchers("/actuator/health/**", "/actuator/info").permitAll()
                        .pathMatchers("/oauth2/**", "/login/oauth2/**").permitAll()
                        .pathMatchers(HttpMethod.POST, "/auth/logout").permitAll()
                        .pathMatchers("/auth/me", "/api/**").authenticated()
                        .anyExchange().denyAll())
                .cors(_ -> {
                })
                // The BFF session cookie is explicitly SameSite=Lax. State-changing endpoints
                // must continue to use unsafe HTTP methods; GET endpoints must remain read-only.
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .exceptionHandling(errors -> errors
                        .authenticationEntryPoint((exchange, exception) -> {
                            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
                            return exchange.getResponse().setComplete();
                        })
                        .accessDeniedHandler((exchange, exception) -> {
                            exchange.getResponse().setStatusCode(HttpStatus.FORBIDDEN);
                            return exchange.getResponse().setComplete();
                        }))
                .oauth2Login(oauth -> oauth
                        .authorizedClientRepository(authorizedClients)
                        .authorizationRequestResolver(authorizationRequestResolver)
                        .authenticationSuccessHandler(loginSuccessHandler)
                        .authenticationFailureHandler(loginFailureHandler))
                .oauth2Client(oauth -> oauth
                        .authorizedClientRepository(authorizedClients))
                .logout(logout -> logout
                        .logoutUrl("/auth/logout")
                        .logoutHandler(logoutHandler)
                        .logoutSuccessHandler(
                                new HttpStatusReturningServerLogoutSuccessHandler(HttpStatus.NO_CONTENT)))
                .httpBasic(ServerHttpSecurity.HttpBasicSpec::disable)
                .formLogin(ServerHttpSecurity.FormLoginSpec::disable)
                .build();
    }

    @Bean
    CorsConfigurationSource corsConfigurationSource(AuthGatewayProperties properties) {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(List.of(properties.frontendOrigin().toString()));
        configuration.setAllowedMethods(List.of("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"));
        configuration.setAllowedHeaders(List.of("Content-Type", "Accept"));
        configuration.setAllowCredentials(true);
        configuration.setMaxAge(3600L);
        return exchange -> configuration;
    }
}
