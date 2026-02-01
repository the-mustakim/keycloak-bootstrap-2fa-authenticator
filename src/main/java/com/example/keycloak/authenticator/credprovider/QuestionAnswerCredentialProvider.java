package com.example.keycloak.authenticator.credprovider;

import com.example.keycloak.authenticator.credmodel.QuestionAnswerCredentialModel;
import org.keycloak.common.util.Time;
import org.keycloak.credential.*;
import org.keycloak.credential.hash.PasswordHashProvider;
import org.keycloak.models.KeycloakSession;
import org.jboss.logging.Logger;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserCredentialModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.credential.PasswordCredentialModel;

/**
 * CredentialProvider implementation for the "Secret Question / Answer" credential.
 *
 * Responsibilities of this class:
 * - Define the credential TYPE handled by this provider
 * - Create and delete secret-question credentials for a user
 * - Validate user-provided answers during authentication
 * - Expose metadata so Keycloak can display this credential in UI / flows
 *
 * Who uses this class:
 * - Called by custom Authenticators via CredentialValidator
 * - Called by Keycloak internally when checking if a user is configured
 * - Used during authentication flows (e.g., 2FA step)
 */
public class QuestionAnswerCredentialProvider
        implements CredentialProvider<QuestionAnswerCredentialModel>, CredentialInputValidator {

    private static final Logger logger =
            Logger.getLogger(QuestionAnswerCredentialProvider.class);

    /**
     * Keycloak session, provided per-request.
     *
     * Used to:
     * - Resolve PasswordHashProvider
     * - Access realm / user context indirectly
     */
    protected KeycloakSession keycloakSession;

    /**
     * Constructor called by QuestionAnswerCredentialProviderFactory.
     *
     * Who calls this:
     * - Keycloak runtime when resolving this provider via session.getProvider(...)
     */
    public QuestionAnswerCredentialProvider(KeycloakSession keycloakSession){
        this.keycloakSession = keycloakSession;
    }

    /**
     * Returns the credential type supported by this provider.
     *
     * Who calls this:
     * - Keycloak when routing credential operations
     * - Authenticators checking credential compatibility
     */
    @Override
    public String getType(){
        return QuestionAnswerCredentialModel.TYPE;
    }

    /**
     * Converts a generic CredentialModel (from DB) into
     * a strongly-typed QuestionAnswerCredentialModel.
     *
     * Who calls this:
     * - Keycloak when loading credentials
     * - isValid() during authentication
     */
    @Override
    public QuestionAnswerCredentialModel getCredentialFromModel(CredentialModel model) {
        return QuestionAnswerCredentialModel.createFromCredentialModel(model);
    }

    /**
     * Persists a new Secret Question credential for a user.
     *
     * Who calls this:
     * - RequiredAction when user sets up the secret question
     * - Admin or programmatic credential creation
     */
    @Override
    public CredentialModel createCredential(
            RealmModel realm,
            UserModel user,
            QuestionAnswerCredentialModel credentialModel) {

        // Ensure creation timestamp is set before persisting
        if(credentialModel.getCreatedDate()==null){
            credentialModel.setCreatedDate(Time.currentTimeMillis());
        }

        // Delegate persistence to Keycloak credential manager
        return user.credentialManager()
                .createStoredCredential(credentialModel);
    }

    /**
     * Deletes an existing Secret Question credential by ID.
     *
     * Who calls this:
     * - Admin Console
     * - User credential removal flows (if enabled)
     */
    @Override
    public boolean deleteCredential(
            RealmModel realm,
            UserModel user,
            String credentialId) {

        return user.credentialManager()
                .removeStoredCredentialById(credentialId);
    }

    /**
     * Validates the user-provided answer during authentication.
     *
     * This method:
     * - Extracts the stored credential
     * - Reconstructs the password hash metadata
     * - Verifies the provided answer using PasswordHashProvider
     *
     * Who calls this:
     * - Custom Authenticator via CredentialValidator
     * - Keycloak authentication engine during login flow
     */
    @Override
    public boolean isValid(
            RealmModel realm,
            UserModel user,
            CredentialInput input) {

        if (!(input instanceof UserCredentialModel userInput)) return false;
        if (!getType().equals(userInput.getType())) return false;

        String credentialId = userInput.getCredentialId();
        if (credentialId == null) return false;

        CredentialModel stored =
                user.credentialManager().getStoredCredentialById(credentialId);

        if (stored == null) return false;

        QuestionAnswerCredentialModel model =
                getCredentialFromModel(stored);

        PasswordHashProvider hashProvider =
                keycloakSession.getProvider(
                        PasswordHashProvider.class,
                        model.getQuestionAnswerCredentialData().getAlgorithm()
                );

        if (hashProvider == null) return false;

        PasswordCredentialModel pcm =
                PasswordCredentialModel.createFromValues(
                        model.getQuestionAnswerCredentialData().getAlgorithm(),
                        model.getQuestionAnswerSecretData().getSalt(),
                        model.getQuestionAnswerCredentialData().getHashIterations(),
                        model.getQuestionAnswerSecretData().getHashedAnswer()
                );

        return hashProvider.verify(
                userInput.getChallengeResponse(),
                pcm
        );
    }

    /**
     * Checks whether this provider supports the given credential type.
     *
     * Who calls this:
     * - Keycloak credential routing logic
     */
    @Override
    public boolean supportsCredentialType(String credentialType) {
        return getType().equals(credentialType);
    }

    /**
     * Checks whether the user has this credential configured.
     *
     * Used by:
     * - Conditional flows
     * - configuredFor() checks in Authenticators
     */
    @Override
    public boolean isConfiguredFor(
            RealmModel realm,
            UserModel user,
            String credentialType) {
        if (!getType().equals(credentialType)) return false;
        // Return true if the stream is NOT empty
        return user.credentialManager().getStoredCredentialsByTypeStream(getType()).findAny().isPresent();
    }

    /**
     * Provides metadata about this credential type for Keycloak UI and flows.
     *
     * Who uses this:
     * - Admin Console
     * - Account Console
     * - Credential management screens
     */
    @Override
    public CredentialTypeMetadata getCredentialTypeMetadata(
            CredentialTypeMetadataContext context) {
        return CredentialTypeMetadata.builder()
                .type(getType())
                .category(CredentialTypeMetadata.Category.TWO_FACTOR)
                .displayName("Secret Question")
                .helpText("Answer to a secret question")
                .removeable(true)
                .createAction(null)
                .updateAction(null)
                .build(keycloakSession);

    }

}
