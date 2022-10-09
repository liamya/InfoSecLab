package schnorr;
/**
 * a solution to the schnorr EUF game, i.e. a pair of a message and a signature
 * a signature is valid if c = H(message,g^s*pk^-c)
 * @param E the type of integer used as exponents in the signature
 */
public class SchnorrSolution<E> {
    /**
     * the message
     */
    public final String message;
    /**
     * the signature
     */
    public final SchnorrSignature<E> signature;

    public SchnorrSolution(String message, SchnorrSignature<E> signature) {
        this.message = message;
        this.signature = signature;
    }
}
