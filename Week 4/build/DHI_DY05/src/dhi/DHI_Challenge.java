package dhi;

import java.math.BigInteger;

import genericGroups.IGroupElement;

/**
 * This class is a container object for a q-type Computational Diffie-Hellman
 * challenge tuple.
 * <p>
 * A q-type DHI tuple consists of q + 1 group elements: a generator g, g^s,
 * g^{s^2}, g^{s^3}, ..., g^{s^{q}}.
 * <p>
 * A correct solution for this DHI tuple is the group element g^{1/s}
 * 
 * @param G this type determines the type of group elements of this challenge.
 */
public class DHI_Challenge {

    private final IGroupElement[] elements;

    /**
     * Creates a new DHI challenge.
     * 
     * @param generator A generator of the group.
     * @param s         The secret exponent.
     * @param q      The number of elements of the challenge (including
     *                  generator). I.e. size = q + 1.
     */
    public DHI_Challenge(IGroupElement generator, BigInteger s, int q) {
        this.elements = new IGroupElement[q + 1];
        for (int i = 0; i < q + 1; ++i) {
            elements[i] = generator.power(s.pow(i));
        }
    }

    /**
     * Returns the group element g^{s^i}
     * 
     * @param i
     * @return g^{s^i}
     */
    public IGroupElement get(int i) {
        return elements[i];
    }

    /**
     * Returns the size of this challenge.
     * 
     * @return The number q + 1. I.e. this challenge is of the form (g, g^s,
     *         g^{s^2}, ..., g^{s^{q}})
     */
    public int size() {
        return elements.length;
    }
}
