package com.example.keycloak.authenticator.actprovider;

import org.keycloak.Config;
import org.keycloak.authentication.RequiredActionFactory;
import org.keycloak.authentication.RequiredActionProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;

/**
 * Factory class for QuestionAnswerRequiredActionProvider.
 *
 * Responsibilities of this class:
 * - Registers the Secret Question required action with Keycloak
 * - Creates instances of the RequiredActionProvider
 * - Provides metadata used by the Admin Console
 *
 * This factory is discovered by Keycloak via:
 * META-INF/services/org.keycloak.authentication.RequiredActionFactory
 */
public class QuestionAnswerRequiredActionProviderFactory
        implements RequiredActionFactory {

    /**
     * Unique provider ID for this required action.
     *
     * Used to:
     * - Register the required action
     * - Reference it from authenticators or flows
     */
    public static final String PROVIDER_ID = "secret-question-required-action";

    /**
     * Singleton instance of the required action provider.
     *
     * Required actions are typically stateless and reused.
     */
    private static final QuestionAnswerRequiredActionProvider SINGLETON =
            new QuestionAnswerRequiredActionProvider();

    /**
     * Display name shown in the Admin Console
     * under Authentication → Required Actions.
     *
     * Who uses this:
     * - Admin Console UI
     */
    @Override
    public String getDisplayText() {
        return "Configure Secret Question";
    }

    /**
     * Creates (or returns) a RequiredActionProvider instance.
     *
     * Who calls this:
     * - Keycloak runtime when executing required actions
     */
    @Override
    public RequiredActionProvider create(KeycloakSession session) {
        // Create and return your RequiredActionProvider implementation
        return SINGLETON;
    }

    /**
     * Initialization hook called when Keycloak boots.
     *
     * Who calls this:
     * - Keycloak during server startup
     */
    @Override
    public void init(Config.Scope config) {
        // Not used in this example
    }

    /**
     * Post-initialization hook called after all factories
     * have been initialized.
     *
     * Who calls this:
     * - Keycloak during startup
     */
    @Override
    public void postInit(KeycloakSessionFactory factory) {
        // Not used in this example
    }

    /**
     * Cleanup hook called when the factory is destroyed.
     *
     * Who calls this:
     * - Keycloak during shutdown
     */
    @Override
    public void close() {
        // Not used in this example
    }

    /**
     * Returns the unique ID of this required action.
     *
     * Who calls this:
     * - Keycloak during provider discovery and registration
     */
    @Override
    public String getId() {
        return PROVIDER_ID;
    }

}
