package com.example.keycloak.authenticator.auth;

import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.util.ArrayList;
import java.util.List;

/**
 * [CLASS RESPONSIBILITY]
 * This factory registers the Secret Question Authenticator with Keycloak.
 * It defines how the authenticator is identified, how it appears in the Admin Console,
 * and what configuration settings (like cookie age) are available to administrators.
 *
 * [DISCOVERY]
 * Keycloak discovers this class via: META-INF/services/org.keycloak.authentication.AuthenticatorFactory
 */
public class QuestionAnswerAuthenticatorFactory implements AuthenticatorFactory {

    private static final Logger log = LoggerFactory.getLogger(QuestionAnswerAuthenticatorFactory.class);

    /**
     * Unique provider ID for this authenticator.
     * Matches the ID used by the provider to link runtime logic to flow configuration.
     */
    public static final String PROVIDER_ID = "secret-question-authenticator";

    /**
     * [DESIGN CHOICE] Singleton Pattern.
     * Since the Authenticator is stateless (it relies on the context per request),
     * we reuse a single instance to reduce memory allocation.
     */
    private static final QuestionAnswerAuthenticator SINGLETON = new QuestionAnswerAuthenticator();

    /**
     * List of configuration UI elements shown in the Keycloak Admin Console.
     */
    private static final List<ProviderConfigProperty> configProperties = new ArrayList<>();

    /**
     * Defines selectable execution requirements (REQUIRED, ALTERNATIVE, etc.).
     */
    private static final AuthenticationExecutionModel.Requirement[] REQUIREMENT_CHOICES = {
            AuthenticationExecutionModel.Requirement.REQUIRED,
            AuthenticationExecutionModel.Requirement.ALTERNATIVE,
            AuthenticationExecutionModel.Requirement.DISABLED
    };

    static {
        ProviderConfigProperty property = new ProviderConfigProperty();
        property.setName("cookie.max.age");
        property.setLabel("Trusted Device Cookie Max Age");
        property.setType(ProviderConfigProperty.STRING_TYPE);
        property.setHelpText("Defines how many seconds the browser should be trusted after a successful answer (Default: 30 days).");
        property.setDefaultValue("2592000");
        configProperties.add(property);
    }

    /**
     * [PURPOSE] Returns the unique string identifier for this authenticator.
     * [CALLER] Keycloak during server boot and provider discovery.
     */
    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    /**
     * [PURPOSE] Returns the Authenticator instance to execute logic in the flow.
     * [LOGIC] Returns the pre-initialized SINGLETON.
     * [CALLER] Keycloak runtime whenever the authentication flow hits this execution.
     */
    @Override
    public Authenticator create(KeycloakSession session) {
        return SINGLETON;
    }

    /**
     * [PURPOSE] Defines the available "Requirement" options in the Admin Console.
     * [CALLER] Keycloak Admin UI when an administrator is designing a flow.
     */
    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return REQUIREMENT_CHOICES;
    }

    /**
     * [PURPOSE] Allows Keycloak to trigger 'setRequiredActions' if the user isn't configured.
     * [LOGIC] Set to true to support our "Bootstrap" logic.
     * [CALLER] Keycloak Flow Engine.
     */
    @Override
    public boolean isUserSetupAllowed() {
        return true;
    }

    /**
     * [PURPOSE] Tells Keycloak if this authenticator has a 'Settings' button in the UI.
     * [CALLER] Keycloak Admin Console.
     */
    @Override
    public boolean isConfigurable() {
        return true;
    }

    /**
     * [PURPOSE] Returns the list of properties to build the configuration UI.
     * [CALLER] Keycloak Admin Console when clicking 'Settings' on this authenticator.
     */
    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return configProperties;
    }

    /**
     * [PURPOSE] The text shown in the flow designer list.
     * [CALLER] Keycloak Admin Console.
     */
    @Override
    public String getDisplayType() {
        return "Secret Question Authenticator";
    }

    /**
     * [PURPOSE] Tooltip/help text for admins.
     * [CALLER] Keycloak Admin Console.
     */
    @Override
    public String getHelpText() {
        return "Prompts user to answer a secret question during login. Supports trusted device cookies.";
    }

    /**
     * [PURPOSE] Groups the authenticator under a category in the flow designer.
     * [CALLER] Keycloak Admin Console.
     */
    @Override
    public String getReferenceCategory() {
        return "Secret Question";
    }

    /**
     * [PURPOSE] Early boot initialization.
     * [CALLER] Keycloak Server during startup.
     */
    @Override
    public void init(Config.Scope scope) {
        log.debug("Initializing Secret Question Authenticator Factory [ID: {}]", PROVIDER_ID);
    }

    /**
     * [PURPOSE] Post-boot operations after all providers are ready.
     * [CALLER] Keycloak Server.
     */
    @Override
    public void postInit(KeycloakSessionFactory factory) {
        log.info("Secret Question Authenticator Factory registered successfully.");
    }

    /**
     * [PURPOSE] Cleanup during server shutdown.
     * [CALLER] Keycloak Server.
     */
    @Override
    public void close() {
        log.debug("Closing Secret Question Authenticator Factory.");
    }
}