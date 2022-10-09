package schnorr;
/**
 * class capturing schnorr public keys
 * @param G the type of group elements used for this public key
 */
public class Schnorr_PK<G> {
    /**
     * the public key as a group element
     */
    public final G key;
    /**
     * the group generator
     */
    public final G base;

    public Schnorr_PK(G base, G key) {
        this.base = base;
        this.key = key;
    }
}