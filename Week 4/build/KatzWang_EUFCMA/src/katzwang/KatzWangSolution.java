package katzwang;

/**
 * a message signature pair to be submitted by an adversary as a solution
 */
public class KatzWangSolution<E> {
    /**
     * the message that the signature is on
     */
    public final String message;
    /**
     * the signature
     */
    public final KatzWangSignature<E> signature;

    public KatzWangSolution(String message, KatzWangSignature<E> sig) {
        this.message = message;
        this.signature = sig;
    }
}
