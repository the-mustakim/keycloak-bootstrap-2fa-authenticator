package com.example.keycloak.authenticator.credmodel;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * [CLASS RESPONSIBILITY]
 * This class acts as a metadata container for the Secret Question.
 * It is serialized into a JSON string and stored in the 'credential_data' column
 * of the Keycloak 'credential' table.
 *
 * [SECURITY NOTE]
 * This class MUST NOT store the hashed answer or the salt. Those are stored
 * separately in the 'secret_data' column via the {@link QuestionAnswerSecretData} class.
 */
@JsonIgnoreProperties(ignoreUnknown = true) // Design Choice: Prevents failures if future Keycloak versions add metadata
public class QuestionAnswerCredentialData {

    private final String question;
    private final String algorithm;
    private final int hashIterations;

    /**
     * [PURPOSE] Reconstructs the object from stored JSON.
     * [LOGIC] Uses Jackson's @JsonCreator to map JSON keys directly to final fields.
     * [CALLER] Jackson (via Keycloak's JsonSerialization utility) when loading credentials from the DB.
     *
     * @param question the security question
     * @param algorithm the hashing algorithm used (e.g., pbkdf2-sha256)
     * @param hashIterations complexity of the hash
     */
    @JsonCreator
    public QuestionAnswerCredentialData(
            @JsonProperty("question") String question,
            @JsonProperty("algorithm") String algorithm,
            @JsonProperty("hashIterations") int hashIterations) {
        this.question = question;
        this.algorithm = algorithm;
        this.hashIterations = hashIterations;
    }

    /**
     * [PURPOSE] Provides the question text for UI rendering.
     * [CALLER] The Authenticator when building the challenge form.
     */
    public String getQuestion() {
        return question;
    }

    /**
     * [PURPOSE] Identifies which hashing provider to use for verification.
     * [CALLER] The CredentialProvider during validation.
     */
    public String getAlgorithm() {
        return algorithm;
    }

    /**
     * [PURPOSE] Provides the iteration count for the hashing provider.
     * [CALLER] The CredentialProvider during validation.
     */
    public int getHashIterations() {
        return hashIterations;
    }
}