package cdh;

/**
 * This class is a container object for a Computational Diffie-Hellman challenge
 * tuple.
 * <p>
 * A CDH tuple consists of three group elements: a generator g, a second element
 * g^x and a third group element g^y. A CDH tuple represents the problem of
 * multiplying in the exponent i.e. computing g^(x*y) when only given g, g^x and
 * g^y.
 * <p>
 * When
 * given a CDH challenge (g, g^x, g^y) from a CDH challenger, usually x and
 * y were drawn independently and uniformly at random.
 * <p>
 * A correct solution for this CDH tuple is a group element whose exponent is x
 * * y.
 * 
 * @param G this type determines the type of group elements of this challenge.
 */
public class CDH_Challenge<G> {
    /**
     * A generator of the group. Usually an encoding of one.
     */
    public final G generator;
    /**
     * A group element of the form g^x, where g is the generator in this tuple.
     * Usually, g^x was drawn uniformly random from the group.
     */
    public final G x;
    /**
     * A group element of the form g^y, where g is the generator in this tuple.
     * Usually, g^y was drawn uniformly random from the group.
     */
    public final G y;

    /**
     * Creates a new CDH challenge.
     * 
     * @param generator A generator of the group.
     * @param x         A group element of the form g^x, where g is the generator in
     *                  this tuple.
     * @param y         A group element of the form g^y, where g is the generator in
     *                  this tuple.
     */
    public CDH_Challenge(G generator, G x, G y) {
        this.generator = generator;
        this.x = x;
        this.y = y;
    }
}
