package com.example.keycloak.authenticator.credmodel;

import org.keycloak.common.util.Time;
import org.keycloak.credential.CredentialModel;
import org.keycloak.util.JsonSerialization;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.io.IOException;

/**
 * [CLASS RESPONSIBILITY]
 * This class acts as a domain-specific wrapper around Keycloak's generic CredentialModel.
 * It handles the serialization of question metadata into 'credentialData' (JSON)
 * and sensitive hashed answers into 'secretData' (JSON).
 */
public class QuestionAnswerCredentialModel extends CredentialModel {

    private static final Logger log = LoggerFactory.getLogger(QuestionAnswerCredentialModel.class);

    /**
     * Unique identifier for this credential type in the Keycloak database.
     */
    public static final String TYPE = "SECRET_QUESTION";

    private final QuestionAnswerCredentialData credentialData;
    private final QuestionAnswerSecretData secretData;

    /**
     * [PURPOSE] Reconstructs a domain model from a database record.
     * [LOGIC] Deserializes JSON strings from the DB into strongly-typed Java objects.
     * [CALLER] The CredentialProvider when loading credentials for verification.
     */
    public static QuestionAnswerCredentialModel createFromCredentialModel(CredentialModel credentialModel) {
        try {
            QuestionAnswerCredentialData jsonCredentialData = JsonSerialization.readValue(
                    credentialModel.getCredentialData(),
                    QuestionAnswerCredentialData.class
            );
            QuestionAnswerSecretData jsonSecretData = JsonSerialization.readValue(
                    credentialModel.getSecretData(),
                    QuestionAnswerSecretData.class
            );
            return buildFromCredentialModel(credentialModel, jsonCredentialData, jsonSecretData);
        } catch (IOException e) {
            log.error("Failed to deserialize Secret Question credential [ID: {}]. Error: {}",
                    credentialModel.getId(), e.getMessage());
            throw new RuntimeException("Could not rehydrate Secret Question model", e);
        }
    }

    /**
     * [PURPOSE] Internal helper to map base metadata (ID, created date) to the new domain object.
     * [CALLER] Internal: createFromCredentialModel().
     */
    private static QuestionAnswerCredentialModel buildFromCredentialModel(
            CredentialModel credentialModel,
            QuestionAnswerCredentialData jsonCredentialData,
            QuestionAnswerSecretData jsonSecretData) {

        QuestionAnswerCredentialModel model = new QuestionAnswerCredentialModel(jsonCredentialData, jsonSecretData);

        model.setUserLabel(credentialModel.getUserLabel());
        model.setCredentialData(credentialModel.getCredentialData());
        model.setSecretData(credentialModel.getSecretData());
        model.setType(TYPE);
        model.setId(credentialModel.getId());
        model.setCreatedDate(credentialModel.getCreatedDate());
        return model;
    }

    /**
     * [PURPOSE] Factory method for creating a brand new credential (e.g., during setup).
     * [LOGIC] Initializes domain objects and triggers the serialization to JSON.
     * [CALLER] RequiredActionProvider or Authenticator during the enrollment phase.
     */
    public static QuestionAnswerCredentialModel createSecretQuestion(
            String question,
            String algorithm,
            int hashIterations,
            String hashedAnswer,
            byte[] salt
    ) {
        QuestionAnswerCredentialModel model = new QuestionAnswerCredentialModel(
                question, algorithm, hashIterations, hashedAnswer, salt);

        model.fillCredentialModelFields();
        return model;
    }

    /**
     * [PURPOSE] Converts Java objects into JSON strings for database persistence.
     * [LOGIC] Uses Keycloak's JsonSerialization to ensure compatibility with the server's Jackson config.
     * [CALLER] Internal: createSecretQuestion().
     */
    private void fillCredentialModelFields() {
        try {
            setCredentialData(JsonSerialization.writeValueAsString(credentialData));
            setSecretData(JsonSerialization.writeValueAsString(secretData));
        } catch (IOException e) {
            log.error("Critical Failure: Could not serialize Secret Question for storage.");
            throw new IllegalStateException("Serialization failed", e);
        }
        setType(TYPE);
        setCreatedDate(Time.currentTimeMillis());
    }

    /**
     * Constructor for initial creation.
     */
    private QuestionAnswerCredentialModel(String question, String algorithm, int hashIterations, String hashedAnswer, byte[] salt) {
        this.credentialData = new QuestionAnswerCredentialData(question, algorithm, hashIterations);
        this.secretData = new QuestionAnswerSecretData(hashedAnswer, salt);
    }

    /**
     * Constructor for reconstruction from database.
     */
    private QuestionAnswerCredentialModel(QuestionAnswerCredentialData credentialData, QuestionAnswerSecretData secretData) {
        this.credentialData = credentialData;
        this.secretData = secretData;
    }

    /**
     * [PURPOSE] Provides access to non-sensitive question metadata.
     */
    public QuestionAnswerCredentialData getQuestionAnswerCredentialData() {
        return credentialData;
    }

    /**
     * [PURPOSE] Provides access to the hash and salt for verification.
     */
    public QuestionAnswerSecretData getQuestionAnswerSecretData() {
        return secretData;
    }
}