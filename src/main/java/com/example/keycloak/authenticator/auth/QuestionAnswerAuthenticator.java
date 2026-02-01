package com.example.keycloak.authenticator.auth;
import com.example.keycloak.authenticator.actprovider.QuestionAnswerRequiredActionProviderFactory;
import com.example.keycloak.authenticator.credmodel.QuestionAnswerCredentialModel;
import com.example.keycloak.authenticator.credprovider.QuestionAnswerCredentialProvider;
import com.example.keycloak.authenticator.credprovider.QuestionAnswerCredentialProviderFactory;
import jakarta.ws.rs.core.Cookie;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.NewCookie;
import jakarta.ws.rs.core.Response;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.CredentialValidator;
import org.keycloak.credential.CredentialModel;
import org.keycloak.credential.CredentialProvider;
import org.keycloak.models.*;

import java.net.URI;

/**
 * Authenticator implementation for Secret Question / Answer authentication.
 *
 * Responsibilities of this class:
 * - Acts as an authentication step inside a Keycloak authentication flow
 * - Renders the secret question form
 * - Processes the submitted answer
 * - Delegates answer validation to QuestionAnswerCredentialProvider
 * - Optionally bypasses the step using a browser cookie
 *
 * Where this class is used:
 * - Added as an execution inside a Keycloak Authentication Flow
 * - Invoked by Keycloak during browser login or other bound flows
 */
public class QuestionAnswerAuthenticator
        implements Authenticator, CredentialValidator<QuestionAnswerCredentialProvider> {

    /**
     * Name of the cookie used to remember that the secret question
     * has already been answered on this browser.
     */
    private static final String COOKIE_NAME = "SECRET_QUESTION_ANSWERED";

    /**
     * Indicates whether this authenticator requires a user to already
     * be identified before execution.
     *
     * Returning true means:
     * - A previous authenticator (e.g., Username/Password) must have
     *   already associated a UserModel with the flow.
     *
     * Who calls this:
     * - Keycloak authentication engine when evaluating flow order
     */
    @Override
    public boolean requiresUser() {
        return true;
    }

    /**
     * Returns the CredentialProvider used by this authenticator.
     *
     * This allows the authenticator to:
     * - Validate user input
     * - Access stored credentials
     *
     * Who calls this:
     * - Keycloak via CredentialValidator interface
     * - Internal methods in this authenticator
     */
    @Override
    public QuestionAnswerCredentialProvider getCredentialProvider(
            KeycloakSession session
    ){
        return (QuestionAnswerCredentialProvider)session.getProvider(CredentialProvider.class,QuestionAnswerCredentialProviderFactory.PROVIDER_ID);
    }
    /**
     * Checks whether the current user has this authenticator configured.
     *
     * This determines whether:
     * - The authenticator should execute normally
     * - Or a required action should be triggered
     *
     * Who calls this:
     * - Keycloak flow engine before executing this authenticator
     */
    @Override
    public boolean configuredFor(
            KeycloakSession keycloakSession,
            RealmModel realmModel,
            UserModel userModel) {

        return getCredentialProvider(keycloakSession)
                .isConfiguredFor(
                        realmModel,
                        userModel,
                        QuestionAnswerCredentialModel.TYPE
                );
    }

    /**
     * Registers required actions if the user is not configured
     * for this authenticator.
     *
     * This method is called only if:
     * - configuredFor() returns false
     * - The AuthenticatorFactory allows user setup
     *
     * Who calls this:
     * - Keycloak flow engine
     *
     * Note:
     * - Currently commented out
     * - Intended to trigger Secret Question setup
     */
    @Override
    public void setRequiredActions(
            KeycloakSession keycloakSession,
            RealmModel realmModel,
            UserModel userModel) {

         userModel.addRequiredAction(
             QuestionAnswerRequiredActionProviderFactory.PROVIDER_ID
         );
    }

    /**
     * Initial entry point when this authenticator is reached in the flow.
     *
     * Responsibilities:
     * - Check if the browser already has a valid cookie
     * - If yes → mark execution as successful
     * - If no → render the secret question form
     *
     * Who calls this:
     * - Keycloak authentication flow engine
     */
    @Override
    public void authenticate(AuthenticationFlowContext context) {
        // 1. Check for the "Trusted Device" cookie
        if (hasCookie(context)) {
            context.success();
            return;
        }

        // 2. CRITICAL: Ensure a user has actually been identified by the previous step (Password)
        UserModel user = context.getUser();
        if (user == null) {
            // This usually means the flow is misconfigured and this step is running too early
            context.attempted();
            return;
        }

        // 3. Attempt to get the user's specific credential
        QuestionAnswerCredentialProvider provider = getCredentialProvider(context.getSession());
        QuestionAnswerCredentialModel model = provider.getDefaultCredential(
                context.getSession(), context.getRealm(), user);

        if (model == null) {
            // User hasn't set a question; move to next option (like OTP)
            context.attempted();
            return;
        }

        // 4. Render the form
        context.form().setAttribute("question", model.getQuestionAnswerCredentialData().getQuestion());
        context.form().setAttribute("credentialId", model.getId());
        Response challenge = context.form().createForm("question-answer.ftl");
        context.challenge(challenge);
    }

    /**
     * Processes the form submission from the secret question page.
     *
     * Responsibilities:
     * - Extract user input
     * - Validate the answer
     * - Handle success or failure
     *
     * Who calls this:
     * - Keycloak when the form POST is submitted
     */
    @Override
    public void action(AuthenticationFlowContext authenticationFlowContext) {

        boolean validated = validateAnswer(authenticationFlowContext);

        if (!validated) {
            // We recreate the challenge, but we MUST set the execution ID
            Response challenge = authenticationFlowContext.form()
                    .setError("Wrong Answer!!Try Again")
                    // Re-add the question so the form isn't empty on reload
                    .setAttribute("question", getQuestionFromModel(authenticationFlowContext))
                    // CRITICAL: This allows the "Try Another Way" link to work
                    .setExecution(authenticationFlowContext.getExecution().getId())
                    .createForm("question-answer.ftl");

            authenticationFlowContext.failureChallenge(
                    AuthenticationFlowError.INVALID_CREDENTIALS,
                    challenge
            );
            return;
        }

        // Success path
        setCookie(authenticationFlowContext);
        authenticationFlowContext.success();
    }

    private String getQuestionFromModel(AuthenticationFlowContext context) {
        QuestionAnswerCredentialProvider provider = getCredentialProvider(context.getSession());
        QuestionAnswerCredentialModel model = provider.getDefaultCredential(
                context.getSession(), context.getRealm(), context.getUser());
        return (model != null) ? model.getQuestionAnswerCredentialData().getQuestion() : "Security Question";
    }

    /**
     * Checks whether the browser already has the "answered" cookie.
     *
     * Used to bypass the authenticator on trusted devices.
     *
     * Who calls this:
     * - authenticate()
     */
    protected boolean hasCookie(AuthenticationFlowContext context) {
        Cookie cookie =
                context.getHttpRequest()
                        .getHttpHeaders()
                        .getCookies()
                        .get(COOKIE_NAME);

        return cookie != null;
    }

    /**
     * Validates the submitted secret answer.
     *
     * Responsibilities:
     * - Read form parameters
     * - Resolve the credential ID
     * - Delegate validation to the CredentialProvider
     *
     * Who calls this:
     * - action()
     */
    protected boolean validateAnswer(AuthenticationFlowContext context) {

        MultivaluedMap<String, String> formData =
                context.getHttpRequest().getDecodedFormParameters();

        String secret = formData.getFirst("secret_answer");
        String credentialId = formData.getFirst("credentialId");

        QuestionAnswerCredentialProvider provider = getCredentialProvider(context.getSession());

        // 2. Resolve Credential ID (Priority: Form > Default)
        if (credentialId == null || credentialId.isEmpty()) {
            CredentialModel defaultCred = provider.getDefaultCredential(
                    context.getSession(), context.getRealm(), context.getUser());

            if (defaultCred == null) return false;
            credentialId = defaultCred.getId();
        }

        // 3. Create the input model for validation
        // Use the explicit TYPE constant to avoid getType() resolution issues
        UserCredentialModel input = new UserCredentialModel(
                credentialId,
                QuestionAnswerCredentialModel.TYPE,
                secret
        );

        // 4. Delegate to provider
        return provider.isValid(context.getRealm(), context.getUser(), input);
    }

    /**
     * Sets a cookie indicating that the secret question
     * has been successfully answered.
     *
     * Cookie lifetime can be configured via AuthenticatorConfig.
     *
     * Who calls this:
     * - action() on successful validation
     */
    protected void setCookie(AuthenticationFlowContext context) {

        AuthenticatorConfigModel config =
                context.getAuthenticatorConfig();

        int maxCookieAge = 60 * 60 * 24 * 30; // default: 30 days

        if (config != null) {
            maxCookieAge =
                    Integer.valueOf(
                            config.getConfig().get("cookie.max.age")
                    );
        }

        URI uri =
                context.getUriInfo()
                        .getBaseUriBuilder()
                        .path("realms")
                        .path(context.getRealm().getName())
                        .build();

        addCookie(
                context,
                COOKIE_NAME,
                "true",
                uri.getRawPath(),
                null,
                null,
                maxCookieAge,
                false,
                true
        );
    }

    /**
     * Helper method to create and attach a cookie
     * to the current HTTP request context.
     *
     * Who calls this:
     * - setCookie()
     */
    private void addCookie(
            AuthenticationFlowContext context,
            String secretQuestionAnswered,
            String aTrue,
            String rawPath,
            Object o,
            Object o1,
            int maxCookieAge,
            boolean b,
            boolean b1) {

        NewCookie newCookie = new NewCookie(
                COOKIE_NAME,
                "true",
                rawPath,
                null,
                null,
                maxCookieAge,
                true,
                true
        );

        context.getSession()
                .getContext()
                .getHttpResponse()
                .setCookieIfAbsent(newCookie);
    }

    /**
     * Lifecycle cleanup hook.
     *
     * Who calls this:
     * - Keycloak when the authenticator instance is being destroyed
     */
    @Override
    public void close() {
    }

}
