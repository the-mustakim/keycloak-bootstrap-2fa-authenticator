package com.example.keycloak.authenticator.actprovider;
import com.example.keycloak.authenticator.credmodel.QuestionAnswerCredentialModel;
import com.example.keycloak.authenticator.credprovider.QuestionAnswerCredentialProvider;
import com.example.keycloak.authenticator.credprovider.QuestionAnswerCredentialProviderFactory;
import jakarta.ws.rs.core.MultivaluedMap;
import org.keycloak.authentication.RequiredActionContext;
import org.keycloak.authentication.RequiredActionProvider;
import org.keycloak.credential.CredentialProvider;
import org.keycloak.credential.hash.PasswordHashProvider;
import org.keycloak.models.UserModel;
import org.keycloak.models.credential.PasswordCredentialModel;

/**
 * RequiredActionProvider implementation for Secret Question setup.
 *
 * Responsibilities of this class:
 * - Detect whether the user has configured a secret question
 * - Force the user to configure it after login (one-time action)
 * - Render the setup form
 * - Process and store the secret question credential securely
 *
 * Where this is used:
 * - Triggered AFTER successful authentication
 * - Executed before the user is fully logged in
 */
public class QuestionAnswerRequiredActionProvider implements RequiredActionProvider {

    /**
     * Required Action ID used to register and trigger this action.
     *
     * This must match the ID exposed by the RequiredActionFactory.
     */
    public static final String REQUIRED_ACTION_ID =
            QuestionAnswerRequiredActionProviderFactory.PROVIDER_ID;

    /**
     * Evaluates whether this required action should be triggered.
     *
     * Responsibilities:
     * - Check if the user has already configured the secret question
     * - If not, add this required action to the user
     *
     * Who calls this:
     * - Keycloak after authentication is completed
     * - Before required actions are executed
     */
    @Override
    public void evaluateTriggers(RequiredActionContext requiredActionContext) {

        UserModel user = requiredActionContext.getUser();

        // Resolve the Secret Question CredentialProvider
        CredentialProvider provider = requiredActionContext.getSession()
                .getProvider(
                        CredentialProvider.class,
                        QuestionAnswerCredentialProviderFactory.PROVIDER_ID
                );
        QuestionAnswerCredentialProvider cap =
                (QuestionAnswerCredentialProvider)provider;


        // Check whether the user already has a secret question configured
        boolean configured =
                cap.isConfiguredFor(
                        requiredActionContext.getRealm(),
                        user,
                        QuestionAnswerCredentialModel.TYPE
                );

        // If not configured, force the user to complete this required action
        if (!configured) {
            user.addRequiredAction(REQUIRED_ACTION_ID);
        }
    }

    /**
     * Renders the required action challenge page.
     *
     * Responsibilities:
     * - Display the HTML form for configuring the secret question
     *
     * Who calls this:
     * - Keycloak when this required action must be completed
     */
    @Override
    public void requiredActionChallenge(
            RequiredActionContext requiredActionContext) {

        requiredActionContext.challenge(
                requiredActionContext.form()
                        .createForm("secret-question.ftl")
        );
    }

    /**
     * Processes the form submission for the required action.
     *
     * Responsibilities:
     * - Read submitted question and answer
     * - Validate input
     * - Hash the answer securely
     * - Create and store the Secret Question credential
     * - Mark required action as completed
     *
     * Who calls this:
     * - Keycloak when the required action form is submitted
     */
    @Override
    public void processAction(RequiredActionContext requiredActionContext) {

        MultivaluedMap<String,String> formData =
                requiredActionContext
                        .getHttpRequest()
                        .getDecodedFormParameters();

        String question = formData.getFirst("question");
        String answer = formData.getFirst("secret_answer");

        // Basic validation of user input
        if (question == null || question.trim().isEmpty()
                || answer == null || answer.trim().isEmpty()) {

            requiredActionContext.challenge(
                    requiredActionContext.form()
                            .setError("Both question and answer are required")
                            .createForm("secret-question.ftl")
            );
            return;
        }

         //----------- HASHING SETUP -----------

         //Algorithm and iteration count for hashing the answer
        String algorithm = "pbkdf2-sha256";
        int iterations = 27500;

        //Resolve the PasswordHashProvider for the chosen algorithm
        PasswordHashProvider hashProvider =
                requiredActionContext
                        .getSession()
                        .getProvider(
                                PasswordHashProvider.class,
                                algorithm
                        );

        if (hashProvider == null) {
            requiredActionContext.failure();
            return;
        }

        //Hash the provided answer
        PasswordCredentialModel pcm =
                hashProvider.encodedCredential(answer, iterations);
        String encodedAnswer = pcm.getPasswordSecretData().getValue();
        int iterationsUsed = pcm.getPasswordCredentialData().getHashIterations();
        String algorithmUsed = pcm.getPasswordCredentialData().getAlgorithm();
        byte[] saltUsed = pcm.getPasswordSecretData().getSalt();

        QuestionAnswerCredentialModel credentialModel =
                QuestionAnswerCredentialModel.createSecretQuestion(
                        question.trim(),
                        algorithmUsed,
                        iterationsUsed,
                        encodedAnswer,
                        saltUsed
                );

        requiredActionContext.getUser()
                .credentialManager()
                .createStoredCredential(credentialModel);

        requiredActionContext.success();
    }

    /**
     * Cleanup hook for the required action provider.
     *
     * Who calls this:
     * - Keycloak when the provider is destroyed
     */
    @Override
    public void close() {

    }
}
