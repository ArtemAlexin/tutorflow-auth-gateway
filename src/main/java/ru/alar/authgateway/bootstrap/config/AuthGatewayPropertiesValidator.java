package ru.alar.authgateway.bootstrap.config;

import org.springframework.validation.Errors;
import org.springframework.validation.Validator;

import java.net.URI;
import java.time.Duration;

public final class AuthGatewayPropertiesValidator implements Validator {

    @Override
    public boolean supports(Class<?> type) {
        return AuthGatewayProperties.class.isAssignableFrom(type);
    }

    @Override
    public void validate(Object target, Errors errors) {
        AuthGatewayProperties properties = (AuthGatewayProperties) target;
        validateToken(properties.token(), errors);

        if (properties.frontendOrigin() != null) {
            validateSameOrigin(
                    "loginSuccessUri",
                    properties.frontendOrigin(),
                    properties.loginSuccessUri(),
                    errors);
            validateSameOrigin(
                    "loginFailureUri",
                    properties.frontendOrigin(),
                    properties.loginFailureUri(),
                    errors);
        }
    }

    private static void validateToken(AuthGatewayProperties.Token token, Errors errors) {
        if (token == null) {
            return;
        }
        requirePositive("token.refreshAhead", token.refreshAhead(), errors);
        requirePositive("token.connectTimeout", token.connectTimeout(), errors);
        requirePositive("token.responseTimeout", token.responseTimeout(), errors);
    }

    private static void requirePositive(String field, Duration value, Errors errors) {
        if (value != null && (value.isZero() || value.isNegative())) {
            errors.rejectValue(field, "duration.positive", "Duration must be positive");
        }
    }

    private static void validateSameOrigin(
            String field,
            URI expectedOrigin,
            URI actual,
            Errors errors) {
        if (actual == null) {
            return;
        }
        if (!hasOrigin(expectedOrigin) || !hasOrigin(actual) || !sameOrigin(expectedOrigin, actual)) {
            errors.rejectValue(
                    field,
                    "redirect.origin",
                    "Redirect URI must have the configured frontend origin");
        }
    }

    private static boolean hasOrigin(URI uri) {
        return uri.getScheme() != null && uri.getHost() != null;
    }

    private static boolean sameOrigin(URI first, URI second) {
        return first.getScheme().equalsIgnoreCase(second.getScheme())
                && first.getHost().equalsIgnoreCase(second.getHost())
                && effectivePort(first) == effectivePort(second);
    }

    private static int effectivePort(URI uri) {
        if (uri.getPort() >= 0) {
            return uri.getPort();
        }
        return "https".equalsIgnoreCase(uri.getScheme()) ? 443 : 80;
    }
}
