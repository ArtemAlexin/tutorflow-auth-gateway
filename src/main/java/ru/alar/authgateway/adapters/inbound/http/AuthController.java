package ru.alar.authgateway.adapters.inbound.http;

import lombok.RequiredArgsConstructor;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import ru.alar.authgateway.adapters.inbound.http.dto.MeResponse;
import ru.alar.authgateway.bootstrap.config.AuthGatewayProperties;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public final class AuthController {
    private final AuthGatewayProperties properties;

    @GetMapping("/me")
    public MeResponse me(@AuthenticationPrincipal OidcUser user) {
        return new MeResponse(
                user.getSubject(),
                user.getFullName(),
                user.getEmail(),
                properties.zitadel().organizationId());
    }
}
