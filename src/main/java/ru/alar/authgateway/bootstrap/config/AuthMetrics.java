package ru.alar.authgateway.bootstrap.config;

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import org.springframework.stereotype.Component;

@Component
public final class AuthMetrics {
    private final Counter loginSuccess;
    private final Counter loginFailure;
    private final Counter refreshSuccess;
    private final Counter refreshFailure;
    private final Counter logoutSuccess;

    public AuthMetrics(MeterRegistry registry) {
        this.loginSuccess = registry.counter("auth.login.success");
        this.loginFailure = registry.counter("auth.login.failure");
        this.refreshSuccess = registry.counter("auth.refresh.success");
        this.refreshFailure = registry.counter("auth.refresh.failure");
        this.logoutSuccess = registry.counter("auth.logout.success");
    }

    public void loginSucceeded() {
        loginSuccess.increment();
    }

    public void loginFailed() {
        loginFailure.increment();
    }

    public void refreshSucceeded() {
        refreshSuccess.increment();
    }

    public void refreshFailed() {
        refreshFailure.increment();
    }

    public void logoutSucceeded() {
        logoutSuccess.increment();
    }
}
