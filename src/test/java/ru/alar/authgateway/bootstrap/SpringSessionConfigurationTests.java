package ru.alar.authgateway.bootstrap;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.session.ReactiveSessionRepository;
import org.springframework.session.Session;
import ru.alar.authgateway.support.RedisIntegrationTest;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;

class SpringSessionConfigurationTests extends RedisIntegrationTest {
    @Autowired
    ReactiveSessionRepository<? extends Session> sessions;

    @Test
    void usesSevenDayIdleTimeout() {
        Session session = sessions.createSession().block();

        assertThat(session.getMaxInactiveInterval()).isEqualTo(Duration.ofDays(7));
    }
}
