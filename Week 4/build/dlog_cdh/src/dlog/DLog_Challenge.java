package dlog;

import java.math.BigInteger;

import genericGroups.IBasicGroupElement;

/**
 * This class is a container object for a Discrete Logarithm challenge.
 * <p>
 * A DLog challenge consists of two group elements: a generator g and a second
 * element
 * g^x. A DLog challenge represents the problem of extracting the exponent x of
 * g^x to the base g.
 * <p>
 * When
 * given a DLog challenge (g, g^x) from a DLog challenger, usually x was drawn
 * uniformly at random.
 * <p>
 * A correct solution for this DLog challenge is the discrete logarithm of the
 * second group element relative to the first.
 * 
 * @param G this type determines the type of group elements of this challenge.
 */
public class DLog_Challenge<G extends IBasicGroupElement<G>> {
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
     * Creates a new DLog challenge.
     * 
     * @param generator A generator of the group.
     * @param x         A group element of the form g^x, where g is the generator in
     *                  this tuple.
     */
    public DLog_Challenge(G generator, G x) {
        this.generator = generator;
        this.x = x;
    }
}
