package com.example.keycloak.authenticator.credmodel;
import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * This class represents the secret data for a security question answer.
 * It stores the hashed version of the answer along with the salt used
 * during the hashing process.
 * This ensures that the original answer is never stored in plain text,
 * improving security.
 */
public class QuestionAnswerSecretData {

    /**
     * The hashed value of the user's answer.
     * The original answer cannot be retrieved from this value.
     */
    private final String hashedAnswer;

    /**
     * The salt used while hashing the answer.
     * Salt helps protect against rainbow table and brute-force attacks.
     */
    private final byte[] salt;

    /**
     * Constructor used to create a QuestionAnswerSecretData object.
     * It is annotated with @JsonCreator to allow JSON deserialization.
     *
     * @param answer the hashed version of the answer
     * @param salt the salt used during hashing
     */
    @JsonCreator
    public QuestionAnswerSecretData(
            @JsonProperty("hashedAnswer") String hashedAnswer,
            @JsonProperty("salt") byte[] salt) {
        this.hashedAnswer = hashedAnswer;
        this.salt = (salt == null) ? null : salt.clone();
    }

    /**
     * Returns the hashed answer.
     * @return hashed answer as a String
     */
    public String getHashedAnswer() {
        return hashedAnswer;
    }

    /**
     * Returns the salt used for hashing the answer.
     * @return salt as a byte array
     */
    public byte[] getSalt() {
        return (salt == null) ? null : salt.clone();
    }
}
