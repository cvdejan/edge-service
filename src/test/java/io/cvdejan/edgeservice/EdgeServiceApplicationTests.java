package io.cvdejan.edgeservice;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@Testcontainers
class EdgeServiceApplicationTests {

    private static final int REDIS_PORT = 6379;
    //private static final int KEYCLOACK_PORT = 8080;

    @MockBean
    ReactiveClientRegistrationRepository clientRegistrationRepository;

    @Container
    static GenericContainer<?> redis = new GenericContainer<>(DockerImageName.parse("redis:7.0"))
            .withExposedPorts(REDIS_PORT);

    @DynamicPropertySource
    static void redisProperties(DynamicPropertyRegistry registry) {
        registry.add("spring.data.redis.host", () -> redis.getHost());
        registry.add("spring.data.redis.port", () -> redis.getMappedPort(REDIS_PORT));
    }
/*
    @Container
    static GenericContainer<?> keycloack = new GenericContainer<>(DockerImageName.parse("quay.io/keycloak/keycloak:22.0.1"))
            .withExposedPorts(KEYCLOACK_PORT)
            .withEnv("KEYCLOAK_ADMIN","user")
            .withEnv("KEYCLOAK_ADMIN_PASSWORD","password")
            .withCommand("start-dev");

    @DynamicPropertySource
    static void keyCloackProperties(DynamicPropertyRegistry registry) {
        registry.add("spring.security.oauth2.client.registration.keycloak.client-id", () -> "edge-service");
        registry.add("spring.security.oauth2.client.registration.keycloak.client-secret", () -> "polar-keycloak-secret");
        registry.add("spring.security.oauth2.client.registration.keycloak.scope", () -> "openid");
        registry.add("spring.security.oauth2.client.provider.keycloak.issuer-uri", () -> "http://localhost:8080/realms/PolarBookshop");
    }

    */

    @Test
    void verifyThatSpringContextLoads() {
    }

}
