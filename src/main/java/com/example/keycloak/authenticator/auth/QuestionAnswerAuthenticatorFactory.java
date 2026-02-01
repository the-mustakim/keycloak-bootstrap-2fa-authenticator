package com.example.keycloak.authenticator.auth;

import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.ArrayList;
import java.util.List;

/**
 * Factory class for QuestionAnswerAuthenticator.
 *
 * Responsibilities of this class:
 * - Registers the Secret Question Authenticator with Keycloak
 * - Controls how the authenticator appears and behaves in Admin Console
 * - Defines supported execution requirements (REQUIRED, ALTERNATIVE, etc.)
 * - Exposes configurable properties for this authenticator
 *
 * This class is discovered by Keycloak via:
 * META-INF/services/org.keycloak.authentication.AuthenticatorFactory
 */
public class QuestionAnswerAuthenticatorFactory implements AuthenticatorFactory {

    /**
     * Unique provider ID used to reference this authenticator.
     *
     * Used when:
     * - Binding the authenticator to an authentication flow
     * - Resolving the authenticator at runtime
     */
    public static final String PROVIDER_ID = "secret-question-authenticator";

    /**
     * Singleton instance of the authenticator.
     *
     * Authenticators are typically stateless and reused.
     * Keycloak will call methods on this instance per request.
     */
    private static final QuestionAnswerAuthenticator SINGLETON =
            new QuestionAnswerAuthenticator();

    /**
     * List of configuration properties exposed in the Admin Console
     * when this authenticator is selected in a flow.
     */
    private static final List<ProviderConfigProperty> configProperties =
            new ArrayList<ProviderConfigProperty>();

    /**
     * Defines which execution requirements are allowed for this authenticator.
     *
     * These values appear as selectable options in the Admin Console.
     */
    private static AuthenticationExecutionModel.Requirement[] REQUIREMENT_CHOICES = {
            AuthenticationExecutionModel.Requirement.REQUIRED,
            AuthenticationExecutionModel.Requirement.ALTERNATIVE,
            AuthenticationExecutionModel.Requirement.DISABLED
    };

    /**
     * Static initialization block defining authenticator configuration options.
     *
     * These options are editable per execution in the authentication flow.
     */
    static {
        ProviderConfigProperty property;
        property = new ProviderConfigProperty();
        property.setName("cookie.max.age");
        property.setLabel("Cookie Max Age");
        property.setType(ProviderConfigProperty.STRING_TYPE);
        property.setHelpText("Max age in seconds of the SECRET_QUESTION_COOKIE.");
        configProperties.add(property);
    }

    /**
     * Returns the unique ID of this authenticator factory.
     *
     * Who calls this:
     * - Keycloak during provider discovery and registration
     */
    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    /**
     * Creates (or returns) an Authenticator instance.
     *
     * Who calls this:
     * - Keycloak runtime when executing authentication flows
     *
     * Note:
     * - Returning a singleton is common and recommended
     *   for stateless authenticators
     */
    @Override
    public Authenticator create(KeycloakSession session) {
        return SINGLETON;
    }

    /**
     * Defines which execution requirements are allowed
     * for this authenticator in authentication flows.
     *
     * Who uses this:
     * - Admin Console UI when configuring flows
     */
    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return REQUIREMENT_CHOICES;
    }

    /**
     * Indicates whether users are allowed to set up this authenticator
     * themselves if they are not yet configured.
     *
     * If true:
     * - setRequiredActions() may be invoked
     *
     * Who calls this:
     * - Keycloak flow engine
     */
    @Override
    public boolean isUserSetupAllowed() {
        return true;
    }

    /**
     * Indicates whether this authenticator supports configuration.
     *
     * If true:
     * - Admin Console allows per-execution configuration
     *
     * Who uses this:
     * - Admin Console UI
     */
    @Override
    public boolean isConfigurable() {
        return true;
    }

    /**
     * Returns the list of configuration properties supported
     * by this authenticator.
     *
     * Who uses this:
     * - Admin Console to render configuration form
     */
    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return configProperties;
    }

    /**
     * Display name shown in the Admin Console
     * when selecting this authenticator.
     */
    @Override
    public String getDisplayType() {
        return "Secret Question Authenticator";
    }

    /**
     * Help text shown in the Admin Console tooltip
     * when selecting this authenticator.
     */
    @Override
    public String getHelpText() {
        return "Prompts user to answer a secret question during login";
    }

    /**
     * Category used to group this authenticator
     * in the Admin Console.
     */
    @Override
    public String getReferenceCategory() {
        return "Secret Question";
    }

    /**
     * Initialization hook called when Keycloak boots.
     *
     * Who calls this:
     * - Keycloak during server startup
     */
    @Override
    public void init(Config.Scope scope) { }

    /**
     * Post-initialization hook called after all factories
     * have been initialized.
     *
     * Who calls this:
     * - Keycloak during startup
     */
    @Override
    public void postInit(KeycloakSessionFactory factory) { }

    /**
     * Cleanup hook when the factory is being destroyed.
     *
     * Who calls this:
     * - Keycloak during shutdown
     */
    @Override
    public void close() { }

}
