package com.example.keycloak.authenticator.credprovider;

import com.example.keycloak.authenticator.credmodel.QuestionAnswerCredentialModel;
import org.keycloak.common.util.Time;
import org.keycloak.credential.*;
import org.keycloak.credential.hash.PasswordHashProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserCredentialModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.credential.PasswordCredentialModel;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * [CLASS RESPONSIBILITY]
 * This provider is the "Security Engine" for the Secret Question credential.
 * It manages the lifecycle (creation/deletion) and the verification logic,
 * ensuring answers are checked using secure hashing algorithms rather than plain-text comparison.
 */
public class QuestionAnswerCredentialProvider
        implements CredentialProvider<QuestionAnswerCredentialModel>, CredentialInputValidator {

    private static final Logger log = LoggerFactory.getLogger(QuestionAnswerCredentialProvider.class);

    protected KeycloakSession keycloakSession;

    /**
     * [PURPOSE] Constructor to inject the session context.
     * [CALLER] The Factory class during session initialization.
     */
    public QuestionAnswerCredentialProvider(KeycloakSession keycloakSession) {
        this.keycloakSession = keycloakSession;
    }

    /**
     * [PURPOSE] Returns the unique string ID for this credential type.
     * [CALLER] Keycloak internal routing and Authenticators.
     */
    @Override
    public String getType() {
        return QuestionAnswerCredentialModel.TYPE;
    }

    /**
     * [PURPOSE] Hydrates a domain-specific model from a raw database record.
     * [CALLER] Keycloak when retrieving credentials from the 'credential' table.
     */
    @Override
    public QuestionAnswerCredentialModel getCredentialFromModel(CredentialModel model) {
        return QuestionAnswerCredentialModel.createFromCredentialModel(model);
    }

    /**
     * [PURPOSE] Saves a new credential to the database for a specific user.
     * [CALLER] RequiredActionProvider during the enrollment/setup phase.
     */
    @Override
    public CredentialModel createCredential(RealmModel realm, UserModel user, QuestionAnswerCredentialModel credentialModel) {
        if (credentialModel.getCreatedDate() == null) {
            credentialModel.setCreatedDate(Time.currentTimeMillis());
        }
        log.debug("Persisting new Secret Question for user: {}", user.getUsername());
        return user.credentialManager().createStoredCredential(credentialModel);
    }

    /**
     * [PURPOSE] Removes a credential record from the database.
     * [CALLER] Admin Console or User Account Console.
     */
    @Override
    public boolean deleteCredential(RealmModel realm, UserModel user, String credentialId) {
        log.info("Deleting Secret Question credential {} for user: {}", credentialId, user.getUsername());
        return user.credentialManager().removeStoredCredentialById(credentialId);
    }

    /**
     * [PURPOSE] The core security check. Validates the user's answer.
     * [LOGIC]
     * 1. Loads the hash metadata from the DB.
     * 2. Resolves the correct PasswordHashProvider (e.g., PBKDF2).
     * 3. Performs a secure verification of the input against the stored hash.
     * [CALLER] Custom Authenticator via the 'isValid' check.
     */
    @Override
    public boolean isValid(RealmModel realm, UserModel user, CredentialInput input) {
        // Validation: Ensure input is the correct type
        if (!(input instanceof UserCredentialModel userInput)) return false;
        if (!getType().equals(userInput.getType())) return false;

        String credentialId = userInput.getCredentialId();

        // Load the stored credential from DB
        CredentialModel stored = (credentialId != null)
                ? user.credentialManager().getStoredCredentialById(credentialId)
                : getDefaultCredential(keycloakSession, realm, user);

        if (stored == null) {
            log.warn("Validation failed: No stored credential found for user {}", user.getUsername());
            return false;
        }

        QuestionAnswerCredentialModel model = getCredentialFromModel(stored);

        // Security: Use Keycloak's Hashing SPI to verify the answer
        PasswordHashProvider hashProvider = keycloakSession.getProvider(
                PasswordHashProvider.class,
                model.getQuestionAnswerCredentialData().getAlgorithm()
        );

        if (hashProvider == null) {
            log.error("Security Error: Hash provider '{}' not found for user {}",
                    model.getQuestionAnswerCredentialData().getAlgorithm(), user.getUsername());
            return false;
        }

        // Reconstruct the password model for the hash provider to consume
        PasswordCredentialModel pcm = PasswordCredentialModel.createFromValues(
                model.getQuestionAnswerCredentialData().getAlgorithm(),
                model.getQuestionAnswerSecretData().getSalt(),
                model.getQuestionAnswerCredentialData().getHashIterations(),
                model.getQuestionAnswerSecretData().getHashedAnswer()
        );

        // hashProvider.verify is inherently constant-time to prevent timing attacks
        return hashProvider.verify(userInput.getChallengeResponse(), pcm);
    }

    /**
     * [PURPOSE] Helper to get the primary secret question for a user if multiple exist.
     */
    public QuestionAnswerCredentialModel getDefaultCredential(KeycloakSession session, RealmModel realm, UserModel user) {
        return user.credentialManager().getStoredCredentialsByTypeStream(getType())
                .map(this::getCredentialFromModel)
                .findFirst()
                .orElse(null);
    }

    @Override
    public boolean supportsCredentialType(String credentialType) {
        return getType().equals(credentialType);
    }

    @Override
    public boolean isConfiguredFor(RealmModel realm, UserModel user, String credentialType) {
        if (!getType().equals(credentialType)) return false;
        return user.credentialManager().getStoredCredentialsByTypeStream(getType()).findAny().isPresent();
    }

    /**
     * [PURPOSE] Defines how this credential appears in the Admin UI.
     * [CALLER] Keycloak Admin Console.
     */
    @Override
    public CredentialTypeMetadata getCredentialTypeMetadata(CredentialTypeMetadataContext context) {
        return CredentialTypeMetadata.builder()
                .type(getType())
                .category(CredentialTypeMetadata.Category.TWO_FACTOR)
                .displayName("Secret Question")
                .helpText("A custom security question and answer used for identity verification.")
                .removeable(true)
                .build(keycloakSession);
    }
}