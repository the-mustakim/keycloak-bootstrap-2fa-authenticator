package com.example.keycloak.authenticator.credprovider;

import org.keycloak.credential.CredentialProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * [CLASS RESPONSIBILITY]
 * This factory is the entry point for Keycloak to manage the lifecycle of the
 * Secret Question Credential Provider. It registers the provider into the
 * Keycloak ecosystem and ensures it is available for use in authentication flows.
 *
 * [DISCOVERY]
 * Keycloak finds this class via the file:
 * META-INF/services/org.keycloak.credential.CredentialProviderFactory
 */
public class QuestionAnswerCredentialProviderFactory
        implements CredentialProviderFactory<QuestionAnswerCredentialProvider> {

    private static final Logger log = LoggerFactory.getLogger(QuestionAnswerCredentialProviderFactory.class);

    /**
     * Unique identifier for the credential provider.
     * This ID is used by Authenticators to fetch the provider from the KeycloakSession.
     */
    public static final String PROVIDER_ID = "secret-question-credential";

    /**
     * [PURPOSE] Returns the unique string ID for this provider.
     * [CALLER] Keycloak during server boot and provider registration.
     */
    @Override
    public String getId(){
        return PROVIDER_ID;
    }

    /**
     * [PURPOSE] Instantiates the provider for the current request.
     * [LOGIC] Creates a new instance and injects the current KeycloakSession.
     * Credential providers are typically request-scoped rather than singletons
     * because they interact closely with the session state.
     * [CALLER] Keycloak runtime whenever session.getProvider(CredentialProvider.class, "secret-question-credential") is called.
     */
    @Override
    public QuestionAnswerCredentialProvider create(KeycloakSession session) {
        log.trace("Creating new QuestionAnswerCredentialProvider instance for session: {}", session);
        return new QuestionAnswerCredentialProvider(session);
    }

    /**
     * [PURPOSE] Post-initialization hook called once the server is ready.
     * [CALLER] Keycloak Server during startup.
     */
    @Override
    public void postInit(org.keycloak.models.KeycloakSessionFactory factory) {
        log.info("Secret Question Credential Provider Factory registered successfully [ID: {}]", PROVIDER_ID);
    }
}