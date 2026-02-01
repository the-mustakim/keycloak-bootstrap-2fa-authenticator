package com.example.keycloak.authenticator.credmodel;
import org.keycloak.common.util.Time;
import org.keycloak.credential.CredentialModel;
import org.keycloak.util.JsonSerialization;
import java.io.IOException;
import org.jboss.logging.Logger;

/**
 * Domain-specific CredentialModel for Secret Question authentication.
 * This class acts as a bridge between:
 *  - Keycloak's generic CredentialModel (DB representation)
 *  - Strongly-typed domain objects used by authenticators
 * Responsibilities:
 *  - Encapsulate question metadata (algorithm, iterations)
 *  - Encapsulate sensitive secret data (hashed answer, salt)
 *  - Control creation vs reconstruction lifecycle
 */
public class QuestionAnswerCredentialModel extends CredentialModel {

    private static final Logger LOG =
            Logger.getLogger(QuestionAnswerCredentialModel.class);

    /**
     * Credential type identifier stored in keycloak DB
     * Must match the type referenced by the authenticator and credential provider
     */
    //public static final String TYPE = "SECRET_QUESTION_CONFIG";
    public static final String TYPE = "SECRET_QUESTION";

    /**
     * Non-sensitive metadata (safe to store in credentialData JSON)
     */
    private final QuestionAnswerCredentialData credentialData;

    /**
     * Sensitive material (stored in secretData JSON)
     */
    private final QuestionAnswerSecretData secretData;


    /***
     * Reconstruction path (DB → Domain Object)
     * Called by:
     * - CredentialProvider
     * - Authentication flow during validation
     * Converts raw JSON stored in CredentialModel into strongly-typed objects
     * **/
    public static QuestionAnswerCredentialModel createFromCredentialModel(CredentialModel credentialModel){
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
            LOG.errorf(
                    e,
                    "Failed to deserialize Secret Question credential [credentialId=%s]",
                    credentialModel.getId()
            );
            throw new RuntimeException(e);
        }
    }

    /***
    *  Internal helper method that rehydrates a domain model while preserving Keycloak-managed metadata (id, label, timestamps).
    */
    private static QuestionAnswerCredentialModel buildFromCredentialModel(
            CredentialModel credentialModel,
            QuestionAnswerCredentialData jsonCredentialData,
            QuestionAnswerSecretData jsonSecretData) {

        QuestionAnswerCredentialModel model =
                new QuestionAnswerCredentialModel(jsonCredentialData, jsonSecretData);

        model.setUserLabel(credentialModel.getUserLabel());
        model.setCredentialData(credentialModel.getCredentialData());
        model.setSecretData(credentialModel.getSecretData());
        model.setType(TYPE);
        model.setId(credentialModel.getId());
        model.setCreatedDate(credentialModel.getCreatedDate());
        return model;
    }

    /***
     *  Creation path (Domain Object → DB)
     *  Constructor used exclusively when creating a NEW credential.
     *  - Answer is already hashed
     *  - Salt is cryptographically secure
     *  - Algorithm choice is validated by caller
     */

    private QuestionAnswerCredentialModel(String question, String algorithm, int hashIterations, String hashedAnswer, byte[] salt) {
        credentialData = new QuestionAnswerCredentialData(question, algorithm, hashIterations);
        secretData = new QuestionAnswerSecretData(hashedAnswer, salt);
    }


    /**
     * Entry point for authenticators when registering a new Secret Question.
     * Flow:
     *  1. Authenticator hashes the answer
     *  2. Calls this factory method
     *  3. Model serializes itself for persistence
     * This method MUST be used instead of constructors directly.
     */
    public static QuestionAnswerCredentialModel createSecretQuestion(
            String question,
            String algorithm,
            int hashIterations,
            String hashedAnswer,
            byte[] salt
    ){
        QuestionAnswerCredentialModel credentialModel =
                new QuestionAnswerCredentialModel(question, algorithm, hashIterations, hashedAnswer, salt);

        credentialModel.setCredentialModelFields();
        return credentialModel;
    }

    /**
     * Serializes domain objects into JSON and sets mandatory Keycloak fields.
     * This method defines the persistence contract for this credential type.
     */
    private void setCredentialModelFields(){
        try {
            setCredentialData(JsonSerialization.writeValueAsString(credentialData));
            setSecretData(JsonSerialization.writeValueAsString(secretData));
        } catch (IOException e) {
            LOG.error("Failed to serialize Secret Question credential data", e);
            throw new IllegalStateException(
                    "Failed to deserialize Secret Question credential",
                    e
            );
        }
        setType(TYPE);
        setCreatedDate(Time.currentTimeMillis());
    }

    /**
     * Constructor used internally during reconstruction from persistence.
     */
    private QuestionAnswerCredentialModel(QuestionAnswerCredentialData credentialData, QuestionAnswerSecretData secretData) {
        this.credentialData = credentialData;
        this.secretData = secretData;
    }

    /**
     * @return Non-sensitive credential metadata (question, algorithm, iterations)
     */
    public QuestionAnswerCredentialData getQuestionAnswerCredentialData() {
        return credentialData;
    }

    /**
     * @return Sensitive secret data (hashed answer + salt)
     */
    public QuestionAnswerSecretData getQuestionAnswerSecretData() {
        return secretData;
    }

}
