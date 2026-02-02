package com.example.keycloak.authenticator.actprovider;
import org.keycloak.Config;
import org.keycloak.authentication.RequiredActionFactory;
import org.keycloak.authentication.RequiredActionProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * [CLASS RESPONSIBILITY]
 * This factory is the entry point for Keycloak to discover and initialize the Secret Question
 * Required Action. It manages the lifecycle of the provider and provides metadata
 * (like the display name) to the Keycloak Admin Console.
 *
 * [DISCOVERY]
 * Keycloak finds this class via the file:
 * META-INF/services/org.keycloak.authentication.RequiredActionFactory
 */
public class QuestionAnswerRequiredActionProviderFactory implements RequiredActionFactory {

    private static final Logger log = LoggerFactory.getLogger(QuestionAnswerRequiredActionProviderFactory.class);

    /**
     * Unique provider ID used to reference this action in flows and database records.
     */
    public static final String PROVIDER_ID = "secret-question-required-action";

    /**
     * [DESIGN CHOICE] Singleton Pattern.
     * Since the RequiredActionProvider is stateless, we reuse a single instance
     * to optimize memory usage and reduce Garbage Collection pressure.
     */
    private static final QuestionAnswerRequiredActionProvider SINGLETON =
            new QuestionAnswerRequiredActionProvider();

    /**
     * [PURPOSE] Provides a human-readable name for the Keycloak Admin UI.
     * [CALLER] Keycloak Admin Console when listing available Required Actions.
     */
    @Override
    public String getDisplayText() {
        return "Configure Secret Question";
    }

    /**
     * [PURPOSE] Returns the provider instance to handle the current user's request.
     * [LOGIC] Returns the pre-initialized SINGLETON instance.
     * [CALLER] Keycloak Runtime whenever a user session triggers this required action.
     */
    @Override
    public RequiredActionProvider create(KeycloakSession session) {
        return SINGLETON;
    }

    /**
     * [PURPOSE] Initializes the factory with configuration properties from keycloak.conf or CLI.
     * [CALLER] Keycloak Server during the early boot phase.
     */
    @Override
    public void init(Config.Scope config) {
        log.debug("Initializing Secret Question Required Action Factory [ID: {}]", PROVIDER_ID);
    }

    /**
     * [PURPOSE] Executes logic after all providers in the system have been initialized.
     * [LOGIC] Used here to log a confirmation that the setup was successful.
     * [CALLER] Keycloak Server after the init() phase is complete for all factories.
     */
    @Override
    public void postInit(KeycloakSessionFactory factory) {
        log.info("Secret Question Required Action Factory successfully registered.");
    }

    /**
     * [PURPOSE] Cleanup operations when the server stops.
     * [CALLER] Keycloak Server during shutdown.
     */
    @Override
    public void close() {
        log.debug("Closing Secret Question Required Action Factory.");
    }

    /**
     * [PURPOSE] Returns the unique string identifier for this factory.
     * [CALLER] Keycloak Provider Manager during the discovery and registration process.
     */
    @Override
    public String getId() {
        return PROVIDER_ID;
    }
}