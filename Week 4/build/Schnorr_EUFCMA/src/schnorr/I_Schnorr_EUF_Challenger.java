package schnorr;

import basics.IChallenger;
/**
 * a schnorr signature EUF challenger
 * @param G the group element type used for signatures
 * @param E the exponent type used for signatures
 */
public interface I_Schnorr_EUF_Challenger<G,E> extends IChallenger{
    /**
     * returns a schnorr public key with respect to which signatures need to be forged
     * @return a schnorr public key 
     */
    public Schnorr_PK<G> getChallenge();
    /**
     * a random oracle that maps from M x R to Z_p
     * @param message the message to be hashed
     * @param r the random group element to be used in the signature
     * @return a random hash value from Z_p
     */
    public E hash(String message, G r);
    /**
     * signs a message so that the signature is valid with respect to the public key and the hash function
     * @param message the message to be signed
     * @return a signature
     */
    public SchnorrSignature<E> sign(String message);
}
