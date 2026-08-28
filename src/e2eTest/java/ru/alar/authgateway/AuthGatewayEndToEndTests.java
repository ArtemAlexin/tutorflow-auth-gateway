package ru.alar.authgateway;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.stubbing.StubMapping;
import com.github.tomakehurst.wiremock.verification.LoggedRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.htmlunit.BrowserVersion;
import org.htmlunit.HttpMethod;
import org.htmlunit.Page;
import org.htmlunit.WebClient;
import org.htmlunit.WebRequest;
import org.htmlunit.WebResponse;
import org.htmlunit.html.HtmlElement;
import org.htmlunit.html.HtmlForm;
import org.htmlunit.html.HtmlPage;
import org.htmlunit.http.Cookie;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.session.ReactiveSessionRepository;
import org.springframework.session.Session;
import org.wiremock.spring.ConfigureWireMock;
import org.wiremock.spring.EnableWireMock;
import org.wiremock.spring.InjectWireMock;
import ru.alar.authgateway.bootstrap.AuthGatewayApplication;
import ru.alar.authgateway.support.AuthGatewayE2eTestcontainers;
import ru.alar.authgateway.support.WithAuthGatewayE2eTestcontainers;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.containing;
import static com.github.tomakehurst.wiremock.client.WireMock.getRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.postRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(
        classes = AuthGatewayApplication.class,
        webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = {
                "server.reactive.session.cookie.secure=false",
                "server.reactive.session.cookie.name=TUTORFLOW_SESSION",
                "tutorflow.auth.token.refresh-ahead=5m",
                "tutorflow.auth.zitadel.token-uri=${auth-gateway.e2e.token-endpoint.base-url}/default/token",
                "TUTORFLOW_URI=${auth-gateway.e2e.downstream.base-url}"
        })
@EnableWireMock({
        @ConfigureWireMock(
                name = "token-endpoint",
                baseUrlProperties = "auth-gateway.e2e.token-endpoint.base-url"),
        @ConfigureWireMock(
                name = "downstream",
                baseUrlProperties = "auth-gateway.e2e.downstream.base-url",
                filesUnderClasspath = "wiremock/downstream")
})
@WithAuthGatewayE2eTestcontainers
@Timeout(30)
class AuthGatewayEndToEndTests {
    private static final String SESSION_COOKIE = "TUTORFLOW_SESSION";

    @LocalServerPort
    int port;

    @Autowired
    ReactiveSessionRepository<? extends Session> sessions;

    @InjectWireMock("token-endpoint")
    WireMockServer tokenEndpoint;

    @InjectWireMock("downstream")
    WireMockServer downstream;

    @BeforeEach
    void resetExternalSystems() throws IOException, InterruptedException {
        AuthGatewayE2eTestcontainers.redis().execInContainer("redis-cli", "FLUSHDB");
        tokenEndpoint.resetAll();
        tokenEndpoint.stubFor(post(urlEqualTo("/default/token"))
                .atPriority(10)
                .willReturn(aResponse().proxiedFrom(AuthGatewayE2eTestcontainers.oidcBaseUri().toString())));
        downstream.resetRequests();
    }

    @Test
    @DisplayName("Успешный login создаёт WebSession, обновляет токен и безопасно проксирует запрос")
    void loginCreatesWebSessionRefreshesTokenAndRelaysOnlyServerCredentials() throws Exception {
        try (BrowserSession browser = new BrowserSession(gatewayBaseUri())) {

            LoginResult login = browser.login("alice");

            assertThat(login.authorizationLocation())
                    .contains("prompt=select_account")
                    .contains("code_challenge=")
                    .contains("code_challenge_method=S256");
            assertThat(browser.sessionCookie().isHttpOnly()).isTrue();
            assertThat(browser.sessionCookie().getSameSite()).isEqualToIgnoringCase("Lax");

            Page me = browser.get("/auth/me");
            assertThat(me.getWebResponse().getStatusCode()).isEqualTo(200);
            assertThat(me.getWebResponse().getContentAsString())
                    .contains("alice")
                    .contains("E2E User")
                    .contains("e2e-user@example.test")
                    .contains("e2e-organization");

            Page api = browser.get(
                    "/api/probe",
                    "Authorization", "Bearer browser-supplied-token",
                    "Proxy-Authorization", "Basic attacker");
            assertThat(api.getWebResponse().getStatusCode()).isEqualTo(200);
            assertThat(api.getWebResponse().getContentAsString()).contains("ok");

        tokenEndpoint.verify(postRequestedFor(urlEqualTo("/default/token"))
                .withRequestBody(containing("grant_type=authorization_code"))
                .withRequestBody(containing("code_verifier=")));
        tokenEndpoint.verify(postRequestedFor(urlEqualTo("/default/token"))
                .withRequestBody(containing("grant_type=refresh_token")));

            List<LoggedRequest> downstreamRequests = downstream.findAll(getRequestedFor(urlEqualTo("/probe")));
            assertThat(downstreamRequests).hasSize(1);
            assertThat(downstreamRequests.getFirst().getHeader("Authorization"))
                    .startsWith("Bearer ")
                    .doesNotContain("browser-supplied-token");
            assertThat(downstreamRequests.getFirst().getHeader("Cookie")).isNull();
            assertThat(downstreamRequests.getFirst().getHeader("Proxy-Authorization")).isNull();

            assertThat(sessions.findById(login.sessionId()).block(Duration.ofSeconds(5))).isNotNull();
        }
    }

    @Test
    @DisplayName("invalid_grant удаляет текущую WebSession и не вызывает downstream")
    void invalidGrantInvalidatesPartialBrowserSessionAndSkipsDownstream() throws Exception {
        try (BrowserSession browser = new BrowserSession(gatewayBaseUri())) {
        LoginResult login = browser.login("invalid-grant-user");
        tokenEndpoint.addStubMapping(mapping("wiremock/token-endpoint-failures/invalid-grant.json"));

        Page api = browser.get("/api/probe");

        assertThat(api.getWebResponse().getStatusCode()).isEqualTo(401);
        assertThat(sessions.findById(login.sessionId()).block(Duration.ofSeconds(5))).isNull();
        assertThat(downstream.findAll(getRequestedFor(urlEqualTo("/probe")))).isEmpty();
        assertThat(browser.get("/auth/me").getWebResponse().getStatusCode()).isEqualTo(401);
        }
    }

    @Test
    @DisplayName("Временная ошибка refresh возвращает 503 и позволяет повторить запрос")
    void temporaryTokenFailureReturns503AndSessionRecovers() throws Exception {
        try (BrowserSession browser = new BrowserSession(gatewayBaseUri())) {
        LoginResult login = browser.login("recoverable-user");
        StubMapping tokenFailure = mapping("wiremock/token-endpoint-failures/server-error.json");
        tokenEndpoint.addStubMapping(tokenFailure);

        assertThat(browser.get("/api/probe").getWebResponse().getStatusCode()).isEqualTo(503);
        assertThat(sessions.findById(login.sessionId()).block(Duration.ofSeconds(5))).isNotNull();
        assertThat(downstream.findAll(getRequestedFor(urlEqualTo("/probe")))).isEmpty();

        tokenEndpoint.removeStub(tokenFailure);
        assertThat(browser.get("/api/probe").getWebResponse().getStatusCode()).isEqualTo(200);
        assertThat(sessions.findById(login.sessionId()).block(Duration.ofSeconds(5))).isNotNull();
        }
    }

    @Test
    @DisplayName("Logout удаляет только текущую WebSession и идемпотентен")
    void logoutInvalidatesOnlyCurrentBrowserSessionAndIsIdempotent() throws Exception {
        try (BrowserSession first = new BrowserSession(gatewayBaseUri());
             BrowserSession second = new BrowserSession(gatewayBaseUri())) {
        LoginResult firstLogin = first.login("first-user");
        LoginResult secondLogin = second.login("second-user");

        WebResponse logout = first.post("/auth/logout");

        assertThat(logout.getStatusCode()).isEqualTo(204);
        assertThat(sessions.findById(firstLogin.sessionId()).block(Duration.ofSeconds(5))).isNull();
        assertThat(sessions.findById(secondLogin.sessionId()).block(Duration.ofSeconds(5))).isNotNull();
        assertThat(first.get("/auth/me").getWebResponse().getStatusCode()).isEqualTo(401);
        assertThat(second.get("/auth/me").getWebResponse().getStatusCode()).isEqualTo(200);
        assertThat(first.post("/auth/logout").getStatusCode()).isEqualTo(204);
        }
    }

    @Test
    @DisplayName("Некорректный callback очищает pre-auth сессию и аноним не достигает downstream")
    void invalidCallbackCleansPreAuthenticationSessionAndAnonymousApiNeverReachesDownstream()
            throws Exception {
        try (BrowserSession browser = new BrowserSession(gatewayBaseUri())) {
        Page authorization = browser.get("/oauth2/authorization/zitadel");
        String sessionId = browser.sessionId();

        Page callback = browser.get(
                "/login/oauth2/code/zitadel?code=invalid&state=invalid");

        assertThat(authorization.getWebResponse().getStatusCode()).isEqualTo(302);
        assertThat(callback.getWebResponse().getStatusCode()).isEqualTo(302);
        assertThat(callback.getWebResponse().getResponseHeaderValue("Location"))
                .contains("http://localhost:5173/auth/error");
        assertThat(sessions.findById(sessionId).block(Duration.ofSeconds(5))).isNull();
        assertThat(browser.get("/api/probe").getWebResponse().getStatusCode()).isEqualTo(401);
        assertThat(downstream.findAll(getRequestedFor(urlEqualTo("/probe")))).isEmpty();
        }
    }

    private URI gatewayBaseUri() {
        return URI.create("http://localhost:" + port);
    }

    private static StubMapping mapping(String resource) {
        try (InputStream stream = AuthGatewayEndToEndTests.class.getClassLoader()
                .getResourceAsStream(resource)) {
            if (stream == null) {
                throw new IllegalArgumentException("Missing WireMock mapping: " + resource);
            }
            return StubMapping.buildFrom(new String(stream.readAllBytes(), StandardCharsets.UTF_8));
        } catch (IOException error) {
            throw new IllegalStateException("Failed to read WireMock mapping: " + resource, error);
        }
    }

    private record LoginResult(
            String sessionId,
            String authorizationLocation) {
    }

    private static final class BrowserSession implements AutoCloseable {
        private final URI gateway;
        private final WebClient client = new WebClient(BrowserVersion.CHROME);

        private BrowserSession(URI gateway) {
            this.gateway = gateway;
            client.getOptions().setRedirectEnabled(false);
            client.getOptions().setJavaScriptEnabled(false);
            client.getOptions().setCssEnabled(false);
            client.getOptions().setThrowExceptionOnFailingStatusCode(false);
        }

        private LoginResult login(String username) throws Exception {
            Page authorization = get("/oauth2/authorization/zitadel");
            assertThat(authorization.getWebResponse().getStatusCode()).isEqualTo(302);
            String authorizationLocation = location(authorization);
            assertThat(authorizationLocation).contains("prompt=select_account");

            HtmlPage loginPage = client.getPage(authorizationLocation);
            assertThat(loginPage.getWebResponse().getStatusCode()).isEqualTo(200);
            HtmlForm form = loginPage.getForms().getFirst();
            form.getInputByName("username").setValueAttribute(username);
            form.getTextAreaByName("claims").setText(
                    "{\"name\":\"E2E User\",\"email\":\"e2e-user@example.test\"}");

            HtmlElement submit = loginPage.getFirstByXPath("//*[@type='submit']");
            Page identityCallback = submit.click();
            assertThat(identityCallback.getWebResponse().getStatusCode()).isEqualTo(302);

            Page gatewayCallback = client.getPage(location(identityCallback));
            assertThat(gatewayCallback.getWebResponse().getStatusCode()).isEqualTo(302);
            assertThat(location(gatewayCallback)).isEqualTo("http://localhost:5173/auth/callback");

            return new LoginResult(sessionId(), authorizationLocation);
        }

        private Page get(String path, String... headers) throws Exception {
            var request = new WebRequest(gateway.resolve(path).toURL(), HttpMethod.GET);
            request.setTimeout(Math.toIntExact(Duration.ofSeconds(10).toMillis()));
            for (int index = 0; index < headers.length; index += 2) {
                request.setAdditionalHeader(headers[index], headers[index + 1]);
            }
            return client.getPage(request);
        }

        private WebResponse post(String path) throws Exception {
            var request = new WebRequest(gateway.resolve(path).toURL(), HttpMethod.POST);
            request.setTimeout(Math.toIntExact(Duration.ofSeconds(10).toMillis()));
            request.setRequestBody("");
            return client.loadWebResponse(request);
        }

        private String sessionId() {
            return client.getCookieManager().getCookies().stream()
                    .filter(cookie -> SESSION_COOKIE.equals(cookie.getName()))
                    .map(Cookie::getValue)
                    .findFirst()
                    .orElseThrow();
        }

        private Cookie sessionCookie() {
            return client.getCookieManager().getCookie(SESSION_COOKIE);
        }

        private static String location(Page response) {
            return response.getWebResponse().getResponseHeaderValue("Location");
        }

        @Override
        public void close() {
            client.close();
        }
    }
}
