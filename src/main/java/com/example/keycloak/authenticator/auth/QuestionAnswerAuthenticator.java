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
import org.keycloak.credential.CredentialProvider;
import org.keycloak.models.*;
import org.keycloak.models.credential.OTPCredentialModel;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.net.URI;

/**
 * [CLASS RESPONSIBILITY]
 * This class handles the runtime execution of the Secret Question authentication step.
 * It manages the "Gatekeeper" logic (Bootstrap) to prevent lockouts, handles browser
 * cookies for trusted devices, and coordinates with the CredentialProvider to verify answers.
 */
public class QuestionAnswerAuthenticator implements Authenticator, CredentialValidator<QuestionAnswerCredentialProvider> {

    private static final Logger log = LoggerFactory.getLogger(QuestionAnswerAuthenticator.class);
    private static final String COOKIE_NAME = "SECRET_QUESTION_ANSWERED";

    /**
     * [PURPOSE] Initial entry point for the authentication execution.
     * [LOGIC] Checks for trusted cookies and evaluates if the user needs to be
     * redirected to setup (Bootstrap logic) or challenged with the question form.
     * [CALLER] The Keycloak Authentication Flow Engine when it reaches this execution step.
     */
    @Override
    public void authenticate(AuthenticationFlowContext context) {
        UserModel user = context.getUser();

        // 1. Trusted Device Check: Skip if the browser is already recognized
        if (hasTrustedDeviceCookie(context)) {
            log.info("Trusted device detected for user: {}. Bypassing Secret Question.", user.getUsername());
            context.success();
            return;
        }

        // 2. Configuration Analysis (Bootstrap Logic)
        boolean hasQuestion = configuredFor(context.getSession(), context.getRealm(), user);
        boolean hasOTP = user.credentialManager().isConfiguredFor(OTPCredentialModel.TYPE);

        log.debug("User: {} | HasQuestion: {} | HasOTP: {}", user.getUsername(), hasQuestion, hasOTP);

        // CASE: Completely unconfigured user -> Setup both to prevent lockout
        if (!hasQuestion && !hasOTP) {
            log.info("New user {} detected. Triggering bootstrap setup for OTP and Secret Question.", user.getUsername());
            user.addRequiredAction(QuestionAnswerRequiredActionProviderFactory.PROVIDER_ID);
            user.addRequiredAction(UserModel.RequiredAction.CONFIGURE_TOTP);
            context.success();
            return;
        }

        // CASE: Question missing but has OTP -> Queue question setup but don't block login
        if (!hasQuestion) {
            log.debug("User {} missing Secret Question but has OTP. Queuing setup and skipping step.", user.getUsername());
            user.addRequiredAction(QuestionAnswerRequiredActionProviderFactory.PROVIDER_ID);
            context.attempted();
            return;
        }

        // 3. Render Challenge: Present the question to the user
        renderForm(context, null);
    }

    /**
     * [PURPOSE] Utility to build and send the FreeMarker HTML challenge.
     * [LOGIC] Fetches the user's question, attaches it to the form, and sets the
     * execution ID to maintain the flow state.
     * [CALLER] Internal: authenticate() for first load, or action() for failed attempts.
     */
    private void renderForm(AuthenticationFlowContext context, String errorMessage) {
        QuestionAnswerCredentialProvider provider = getCredentialProvider(context.getSession());
        QuestionAnswerCredentialModel model = provider.getDefaultCredential(
                context.getSession(), context.getRealm(), context.getUser());

        if (model == null) {
            log.error("Logic failure: User {} reached form but has no credential model.", context.getUser().getUsername());
            context.attempted();
            return;
        }

        var form = context.form()
                .setAttribute("question", model.getQuestionAnswerCredentialData().getQuestion())
                .setAttribute("credentialId", model.getId());

        if (errorMessage != null) {
            form.setError(errorMessage);
        }

        // Execution ID is required for Keycloak to map the POST request back to this step
        form.setExecution(context.getExecution().getId());

        Response challenge = form.createForm("question-answer.ftl");
        context.challenge(challenge);
    }

    /**
     * [PURPOSE] Handles the HTTP POST request when the user submits their answer.
     * [LOGIC] Extracts the form data, triggers the credential validation, and
     * either sets a trusted cookie (Success) or re-challenges the user (Failure).
     * [CALLER] The Keycloak Authentication Flow Engine after a form submission.
     */
    @Override
    public void action(AuthenticationFlowContext context) {
        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        String secretInput = formData.getFirst("secret_answer");
        String credentialId = formData.getFirst("credentialId");

        if (secretInput == null || secretInput.trim().isEmpty()) {
            log.warn("User {} submitted an empty answer.", context.getUser().getUsername());
            renderForm(context, "Answer cannot be empty.");
            return;
        }

        UserCredentialModel input = new UserCredentialModel(credentialId, QuestionAnswerCredentialModel.TYPE, secretInput);
        boolean valid = getCredentialProvider(context.getSession()).isValid(context.getRealm(), context.getUser(), input);

        if (valid) {
            log.info("Secret Question verified successfully for user: {}", context.getUser().getUsername());
            setTrustedDeviceCookie(context);
            context.success();
        } else {
            log.warn("Invalid Secret Question attempt for user: {}", context.getUser().getUsername());
            context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS,
                    context.form()
                            .setError("Invalid answer. Please try again.")
                            .setExecution(context.getExecution().getId())
                            .setAttribute("question", getQuestionText(context))
                            .createForm("question-answer.ftl"));
        }
    }

    /**
     * [PURPOSE] Fetches the raw question text for UI display.
     * [CALLER] Internal helper for form rendering.
     */
    private String getQuestionText(AuthenticationFlowContext context) {
        QuestionAnswerCredentialModel model = getCredentialProvider(context.getSession())
                .getDefaultCredential(context.getSession(), context.getRealm(), context.getUser());
        return (model != null) ? model.getQuestionAnswerCredentialData().getQuestion() : "Security Question";
    }

    /**
     * [PURPOSE] Detects the presence of the "Trusted Device" cookie.
     * [CALLER] Internal: authenticate() to decide if the step can be bypassed.
     */
    private boolean hasTrustedDeviceCookie(AuthenticationFlowContext context) {
        Cookie cookie = context.getHttpRequest().getHttpHeaders().getCookies().get(COOKIE_NAME);
        return cookie != null && "true".equals(cookie.getValue());
    }

    /**
     * [PURPOSE] Drops a secure, HttpOnly cookie on the user's browser upon success.
     * [CALLER] Internal: action() upon successful validation of the answer.
     */
    private void setTrustedDeviceCookie(AuthenticationFlowContext context) {
        AuthenticatorConfigModel config = context.getAuthenticatorConfig();
        int maxAge = (config != null && config.getConfig().containsKey("cookie.max.age"))
                ? Integer.parseInt(config.getConfig().get("cookie.max.age"))
                : 2592000; // Default 30 days

        URI baseUri = context.getUriInfo().getBaseUriBuilder().path("realms").path(context.getRealm().getName()).build();

        NewCookie trustedCookie = new NewCookie.Builder(COOKIE_NAME)
                .value("true")
                .path(baseUri.getRawPath())
                .maxAge(maxAge)
                .secure(true)     // Security: Only send over HTTPS
                .httpOnly(true)   // Security: Prevent Javascript from reading the cookie
                .build();

        context.getSession().getContext().getHttpResponse().setCookieIfAbsent(trustedCookie);
    }

    /**
     * [PURPOSE] Tells Keycloak that this authenticator requires a user to be identified first.
     * [CALLER] Keycloak Flow Engine to validate flow configuration.
     */
    @Override
    public boolean requiresUser() { return true; }

    /**
     * [PURPOSE] Manually attaches Required Actions to the user profile.
     * [CALLER] Keycloak if the 'configuredFor' check fails and setup is required.
     */
    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
        user.addRequiredAction(QuestionAnswerRequiredActionProviderFactory.PROVIDER_ID);
    }

    /**
     * [PURPOSE] Checks if the user actually has a secret question credential stored.
     * [CALLER] Keycloak and internal authenticate() logic.
     */
    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return getCredentialProvider(session).isConfiguredFor(realm, user, QuestionAnswerCredentialModel.TYPE);
    }

    /**
     * [PURPOSE] Utility to resolve the CredentialProvider from the session.
     * [CALLER] Various internal methods to interact with the database/hashing logic.
     */
    @Override
    public QuestionAnswerCredentialProvider getCredentialProvider(KeycloakSession session) {
        return (QuestionAnswerCredentialProvider) session.getProvider(CredentialProvider.class, QuestionAnswerCredentialProviderFactory.PROVIDER_ID);
    }

    /**
     * [PURPOSE] Lifecycle cleanup.
     * [CALLER] Keycloak when the session/request ends.
     */
    @Override
    public void close() {}
}