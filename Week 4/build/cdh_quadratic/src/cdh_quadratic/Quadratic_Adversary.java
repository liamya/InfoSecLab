package cdh_quadratic;

import java.math.BigInteger;
import java.util.Random;

import cdh.CDH_Adversary;
import cdh.CDH_Challenge;
import cdh.I_CDH_Challenger;
import genericGroups.AlgebraicGroup;
import genericGroups.GroupElement;
import genericGroups.IGroupElement;

import static utils.NumberUtils.getRandomBigInteger;

/**
 * A quadratic adversary with perfect advantage (in the sense that this
 * adversary will always reliably answer a CDH challeng with g^(aXY + bX + cY +
 * d)).
 * 
 * This adversary has direct access to the group and uses DLog to solve CDH
 * challenges.
 * 
 * If anything should not work during the run of this adversary
 * it will return null as solution to a CDH challenge.
 */
public class Quadratic_Adversary extends CDH_Adversary implements I_Quadratic_Adversary<IGroupElement> {

    /**
     * We use direct access to the group to extract the exponents.
     */
    private AlgebraicGroup<BigInteger> group;

    /**
     * How many times has the run method been called?
     */
    private int calls = 0;

    /**
     * The four random numbers by which this adversary will distort its answer.
     * a should never be zero.
     */
    private BigInteger a, b, c, d;

    public Quadratic_Adversary(AlgebraicGroup<BigInteger> group, Random random) {
        super(group);
        this.group = group;
        var p = group.ring.characteristic();
        a = getRandomBigInteger(random, p);
        while (a.signum() == 0)
            a = getRandomBigInteger(random, p);
        b = getRandomBigInteger(random, p);
        c = getRandomBigInteger(random, p);
        d = getRandomBigInteger(random, p);
    }

    /**
     * Returns the Exponent of g
     * 
     * @param g
     * @return
     */
    private BigInteger decode(IGroupElement g) {
        int handle = ((GroupElement) g).groupElement.handle;
        return group.decode(handle);
    }

    /**
     * Computes the solution of the challenge (g, x, y) that is the group element
     * g^(a x'y' + bx' + cy' + d)
     * for x' = dlog(x) / dlog(g) and y' = dlog(y) / dlog(g).
     * 
     * @param challenge
     * @return
     */
    private IGroupElement getCorrectAnswer(CDH_Challenge<IGroupElement> challenge) {
        var order = group.ring.characteristic();
        var base = decode(challenge.generator);
        var x = decode(challenge.x);
        var y = decode(challenge.y);
        var inv_base = base.modInverse(order);
        x = x.multiply(inv_base).mod(order);
        y = y.multiply(inv_base).mod(order);

        var new_exponent = x.multiply(y).multiply(a).mod(order);
        new_exponent = x.multiply(b).add(new_exponent).mod(order);
        new_exponent = y.multiply(c).add(new_exponent).mod(order);
        new_exponent = d.add(new_exponent).mod(order);
        return challenge.generator.power(new_exponent);
    }

    @Override
    public IGroupElement run(I_CDH_Challenger<IGroupElement> challenger) {
        calls++;
        if (challenger == null)
            throw new NullPointerException("The argument challenger was null!");

        var challenge = challenger.getChallenge();

        if (!isNotNull(challenge))
            return getErrorAnswer();
        if (!usesCorrectGroupElements(challenge))
            return getErrorAnswer();
        return getCorrectAnswer(challenge);
    }

}
