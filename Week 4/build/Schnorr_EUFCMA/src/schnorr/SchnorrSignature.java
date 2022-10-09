package schnorr;
/**
 * a Scnhorr signature consisting of a challenge c and a response s
 * @param E the class for exponents
 */
public class SchnorrSignature<E>  {
    /**
     * the challenge, i.e. hash value
     */
    public final E c;
    /**
     * the response, i.e. cx + r
     */
    public final E s;

    public SchnorrSignature(E c, E s) {
        this.c = c;
        this.s = s;
    }
}
