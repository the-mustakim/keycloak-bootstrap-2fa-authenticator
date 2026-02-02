package com.example.keycloak.authenticator.credmodel;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * [CLASS RESPONSIBILITY]
 * This class handles the storage of the sensitive parts of the credential.
 * It is serialized into JSON and stored in the 'secret_data' column of the database.
 * * [SECURITY NOTE]
 * This contains the hashed answer and the salt. Access to this data should
 * be restricted to the CredentialProvider during the verification phase.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class QuestionAnswerSecretData {

    private final String hashedAnswer;
    private final byte[] salt;

    /**
     * [PURPOSE] Reconstructs the secret data from the database JSON.
     * [LOGIC] Uses defensive copying (.clone()) for the salt to ensure immutability.
     * [CALLER] Jackson JSON provider when loading the credential secret.
     *
     * @param hashedAnswer the PBKDF2 (or other) encoded string
     * @param salt the random bytes used to salt the hash
     */
    @JsonCreator
    public QuestionAnswerSecretData(
            @JsonProperty("hashedAnswer") String hashedAnswer,
            @JsonProperty("salt") byte[] salt) {
        this.hashedAnswer = hashedAnswer;
        // Design Choice: Defensive copy to prevent external modification of the byte array
        this.salt = (salt == null) ? null : salt.clone();
    }

    /**
     * [PURPOSE] Provides the hash for comparison.
     * [CALLER] The CredentialProvider's 'isValid' method.
     */
    public String getHashedAnswer() {
        return hashedAnswer;
    }

    /**
     * [PURPOSE] Provides the salt for the hashing algorithm.
     * [LOGIC] Returns a clone of the byte array to maintain class encapsulation.
     * [CALLER] The CredentialProvider when re-hashing the user's input for comparison.
     */
    public byte[] getSalt() {
        return (salt == null) ? null : salt.clone();
    }
}