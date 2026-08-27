package ru.alar.authgateway.bootstrap.config;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.InMemoryReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.server.DefaultServerOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;
import org.springframework.validation.Validator;
import ru.alar.authgateway.bootstrap.config.AuthGatewayProperties;
import ru.alar.authgateway.bootstrap.config.AuthGatewayPropertiesValidator;

import java.util.List;

@Configuration(proxyBeanMethods = false)
@EnableConfigurationProperties(AuthGatewayProperties.class)
public class OAuth2ClientConfiguration {

    /**
     * Spring Boot looks up this reserved bean name during
     * {@code @ConfigurationProperties} binding. The method is static because
     * the validator is needed before regular configuration beans are created.
     */
    @Bean
    static Validator configurationPropertiesValidator() {
        return new AuthGatewayPropertiesValidator();
    }

    @Bean
    ReactiveClientRegistrationRepository clientRegistrationRepository(
            AuthGatewayProperties properties) {
        var zitadel = properties.zitadel();
        var registration = ClientRegistration
                .withRegistrationId(properties.registrationId())
                .clientId(zitadel.clientId())
                .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
                .scope(List.of(
                        "openid",
                        "profile",
                        "email",
                        "offline_access",
                        "urn:zitadel:iam:org:id:" + zitadel.organizationId(),
                        "urn:zitadel:iam:org:project:id:"
                                + zitadel.tutorflowProjectId() + ":aud"))
                .authorizationUri(zitadel.authorizationUri()
                        .toString())
                .tokenUri(zitadel.tokenUri()
                        .toString())
                .jwkSetUri(zitadel.jwkSetUri()
                        .toString())
                .issuerUri(zitadel.issuerUri()
                        .toString())
                .userInfoUri(zitadel.userInfoUri()
                        .toString())
                .userNameAttributeName(IdTokenClaimNames.SUB)
                .clientSettings(ClientRegistration.ClientSettings.builder()
                        .requireProofKey(true)
                        .build())
                .clientName("ZITADEL")
                .build();

        return new InMemoryReactiveClientRegistrationRepository(registration);
    }

    @Bean
    ServerOAuth2AuthorizationRequestResolver authorizationRequestResolver(
            ReactiveClientRegistrationRepository registrations) {
        var resolver = new DefaultServerOAuth2AuthorizationRequestResolver(registrations);
        resolver.setAuthorizationRequestCustomizer(request ->
                request.additionalParameters(parameters ->
                        parameters.put("prompt", "select_account")));
        return resolver;
    }
}
