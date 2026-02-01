package com.example.keycloak.authenticator.credmodel;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * This class stores metadata related to a security question and
 * the hashing configuration used to protect its answer.
 *
 * It does not store the answer itself, only the information
 * required to verify it securely.
 */
public class QuestionAnswerCredentialData {

    /**
     * The security question presented to the user.
     */
    private final String question;

    /**
     * The hashing algorithm used to hash the answer
     * (e.g., PBKDF2, bcrypt, or SHA-256).
     */
    private final String algorithm;

    /**
     * The number of iterations used during the hashing process.
     * Higher values improve security by increasing computation cost.
     */
    private final int hashIterations;

    /**
     * Constructor used to create a QuestionAnswerCredentialData object.
     * Annotated with @JsonCreator to support JSON deserialization.
     *
     * @param question the security question
     * @param algorithm the hashing algorithm used
     * @param hashIterations number of hashing iterations
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
     * Returns the security question.
     * @return the question as a String
     */
    public String getQuestion() {
        return question;
    }

    /**
     * Returns the hashing algorithm used.
     * @return hashing algorithm name
     */
    public String getAlgorithm() {
        return algorithm;
    }

    /**
     * Returns the number of hash iterations.
     * @return number of iterations
     */
    public int getHashIterations() {
        return hashIterations;
    }
}
