package com.example.keycloak.authenticator.credprovider;

import org.keycloak.credential.CredentialProviderFactory;
import org.keycloak.models.KeycloakSession;

/**
 * Factory class for QuestionAnswerCredentialProvider.
 *
 * Responsibilities of this class:
 * - Registers the Secret Question credential provider with Keycloak
 * - Acts as the entry point for Keycloak to create instances of the provider
 *
 * This class is discovered by Keycloak via:
 * META-INF/services/org.keycloak.credential.CredentialProviderFactory
 */
public class QuestionAnswerCredentialProviderFactory
        implements CredentialProviderFactory<QuestionAnswerCredentialProvider> {

    /**
     * Unique provider ID used by Keycloak to reference this credential provider.
     *
     * This ID is used when:
     * - Resolving the CredentialProvider via KeycloakSession
     * - Linking Authenticators to this credential type
     */
    public static final String PROVIDER_ID = "secret-question-credential";

    /**
     * Returns the unique ID of this CredentialProvider.
     *
     * Who calls this:
     * - Keycloak during provider discovery and registration
     * - Internally when resolving providers by ID
     */
    @Override
    public String getId(){
        return PROVIDER_ID;
    }

    /**
     * Creates a new instance of QuestionAnswerCredentialProvider.
     *
     * Who calls this:
     * - Keycloak runtime whenever a CredentialProvider instance
     *   is required for the current request/session
     *
     * Note:
     * - Providers are typically request-scoped
     * - KeycloakSession is injected to allow access to hashing,
     *   realm, and user context
     */
    @Override
    public QuestionAnswerCredentialProvider create(KeycloakSession session) {
        return new QuestionAnswerCredentialProvider(session);
    }

}
