package katzwang;

/**
 * A Katz Wang PK consisting of a Diffie-Hellman tuple
 * 
 * @param G the group element type for this public key
 */
public class KatzWangPK<G> {
    /**
     * a group generator g
     */
    public final G g;
    /**
     * a second group generator h
     */
    public final G h;
    /**
     * y_1 is g^x
     */
    public final G y_1;
    /**
     * y_2 is h^x
     */
    public final G y_2;

    public KatzWangPK(G g, G h, G y_1, G y_2) {
        this.g = g;
        this.h = h;
        this.y_1 = y_1;
        this.y_2 = y_2;
    }
}
