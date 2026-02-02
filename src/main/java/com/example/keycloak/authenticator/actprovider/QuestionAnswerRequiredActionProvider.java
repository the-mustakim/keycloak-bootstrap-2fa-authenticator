package com.example.keycloak.authenticator.actprovider;

import com.example.keycloak.authenticator.credmodel.QuestionAnswerCredentialModel;
import com.example.keycloak.authenticator.credprovider.QuestionAnswerCredentialProvider;
import com.example.keycloak.authenticator.credprovider.QuestionAnswerCredentialProviderFactory;
import jakarta.ws.rs.core.MultivaluedMap;
import org.keycloak.authentication.RequiredActionContext;
import org.keycloak.authentication.RequiredActionProvider;
import org.keycloak.credential.CredentialProvider;
import org.keycloak.credential.hash.PasswordHashProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.credential.PasswordCredentialModel;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * [CLASS RESPONSIBILITY]
 * This provider handles the "Enrollment" phase of the Secret Question.
 * It is responsible for checking if a user needs to set up their question,
 * rendering the setup UI, and securely hashing/storing the answer.
 */
public class QuestionAnswerRequiredActionProvider implements RequiredActionProvider {

    private static final Logger log = LoggerFactory.getLogger(QuestionAnswerRequiredActionProvider.class);

    /**
     * Unique ID used to link this provider to the Factory.
     */
    public static final String REQUIRED_ACTION_ID = QuestionAnswerRequiredActionProviderFactory.PROVIDER_ID;

    // Security configurations for PBKDF2 hashing
    private static final String DEFAULT_HASH_ALGORITHM = "pbkdf2-sha256";
    private static final int HASH_ITERATIONS = 27500;
    private static final String FORM_NAME = "secret-question.ftl";

    /**
     * [PURPOSE] Automatically determines if this action should be forced upon the user.
     * [LOGIC] It queries the CredentialProvider to see if the user already has a
     * secret question. If not, it adds the Required Action ID to the user's account.
     * [CALLER] Keycloak Authentication Engine immediately after successful login,
     * before the user reaches the application.
     */
    @Override
    public void evaluateTriggers(RequiredActionContext context) {
        UserModel user = context.getUser();
        RealmModel realm = context.getRealm();
        KeycloakSession session = context.getSession();

        log.debug("Evaluating Secret Question triggers for user: {}", user.getUsername());

        QuestionAnswerCredentialProvider provider = (QuestionAnswerCredentialProvider)
                session.getProvider(CredentialProvider.class, QuestionAnswerCredentialProviderFactory.PROVIDER_ID);

        // Logic: Only force setup if the provider exists and the user hasn't finished setup yet
        if (provider != null && !provider.isConfiguredFor(realm, user, QuestionAnswerCredentialModel.TYPE)) {
            log.info("User {} has no Secret Question configured. Adding Required Action: {}",
                    user.getUsername(), REQUIRED_ACTION_ID);
            user.addRequiredAction(REQUIRED_ACTION_ID);
        }
    }

    /**
     * [PURPOSE] Renders the initial setup form.
     * [LOGIC] Instructs Keycloak to display the 'secret-question.ftl' template.
     * [CALLER] Keycloak Required Action Engine when the user has this action
     * assigned to their profile.
     */
    @Override
    public void requiredActionChallenge(RequiredActionContext context) {
        log.debug("Directing user {} to Secret Question setup form.", context.getUser().getUsername());
        context.challenge(context.form().createForm(FORM_NAME));
    }

    /**
     * [PURPOSE] Processes the submission of the setup form.
     * [LOGIC]
     * 1. Validates that inputs are not blank.
     * 2. Uses Keycloak's PasswordHashProvider to hash the answer (we never store plain text).
     * 3. Creates a CredentialModel and persists it via the CredentialManager.
     * 4. Calls context.success() to mark the action as complete.
     * [CALLER] Keycloak Required Action Engine when the user submits the HTML form (POST).
     */
    @Override
    public void processAction(RequiredActionContext context) {
        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();

        String question = formData.getFirst("question");
        String answer = formData.getFirst("secret_answer");

        // 1. Validation Logic
        if (isBlank(question) || isBlank(answer)) {
            log.warn("MFA Setup Validation Failed: User {} submitted empty fields.", context.getUser().getUsername());
            context.challenge(context.form()
                    .setError("Both question and answer are required.")
                    .createForm(FORM_NAME));
            return;
        }

        try {
            // 2. Security: Resolve the hashing algorithm provider
            PasswordHashProvider hashProvider = context.getSession().getProvider(PasswordHashProvider.class, DEFAULT_HASH_ALGORITHM);
            if (hashProvider == null) {
                log.error("Configuration Error: Failed to find hash provider for algorithm: {}", DEFAULT_HASH_ALGORITHM);
                context.failure();
                return;
            }

            // 3. Security: Transform plain-text answer into a secure hash
            // We trim() the answer to prevent login failures caused by accidental trailing spaces
            PasswordCredentialModel pcm = hashProvider.encodedCredential(answer.trim(), HASH_ITERATIONS);

            QuestionAnswerCredentialModel credentialModel = QuestionAnswerCredentialModel.createSecretQuestion(
                    question.trim(),
                    pcm.getPasswordCredentialData().getAlgorithm(),
                    pcm.getPasswordCredentialData().getHashIterations(),
                    pcm.getPasswordSecretData().getValue(),
                    pcm.getPasswordSecretData().getSalt()
            );

            // 4. Persistence: Save to the database
            context.getUser().credentialManager().createStoredCredential(credentialModel);

            log.info("MFA Setup Complete: User {} successfully configured Secret Question.", context.getUser().getUsername());
            context.success();

        } catch (Exception e) {
            // Error Handling: Mask specific system errors from the user while logging details for admins
            log.error("Internal Server Error during MFA setup for user {}: {}", context.getUser().getUsername(), e.getMessage());
            context.challenge(context.form()
                    .setError("An unexpected error occurred. Please try again later.")
                    .createForm(FORM_NAME));
        }
    }

    /**
     * [PURPOSE] Cleanup resources.
     * [CALLER] Keycloak at the end of the request/session lifecycle.
     */
    @Override
    public void close() {
        // Resources are managed by KeycloakSession lifecycle
    }

    /**
     * [PURPOSE] Internal helper to check for null or whitespace strings.
     * [CALLER] Internal processAction() validation.
     */
    private boolean isBlank(String s) {
        return s == null || s.trim().isEmpty();
    }
}