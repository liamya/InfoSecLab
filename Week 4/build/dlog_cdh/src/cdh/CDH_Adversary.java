package cdh;

import java.math.BigInteger;

import genericGroups.AlgebraicGroup;
import genericGroups.GroupElement;
import genericGroups.IGroupElement;

/**
 * A CDH adversary with perfect advantage.
 * This adversary has direct access to the group and uses DLog to solve CDH
 * challenges.
 * 
 * If anything should not work during the run of this adversary
 * it will return null as solution to a CDH challenge.
 */
public class CDH_Adversary implements I_CDH_Adversary<IGroupElement> {

    /**
     * We use direct access to the group to extract the exponents.
     */
    private AlgebraicGroup<BigInteger> group;

    /**
     * How many times has the run method been called?
     */
    private int calls = 0;

    public CDH_Adversary(AlgebraicGroup<BigInteger> group) {
        this.group = group;
    }

    /***
     * Returns true iff challenge and each of its members is not null
     * 
     * @param <E>
     * @param challenge
     * @return
     */
    protected <G> boolean isNotNull(CDH_Challenge<G> challenge) {
        if (challenge == null || challenge.generator == null || challenge.x == null || challenge.y == null)
            return false;
        return true;
    }

    /***
     * Returns true iff each member of challenge is of type GroupElement
     * 
     * @param <G>
     * @param challenge
     * @return
     */
    protected <G> boolean usesCorrectGroupElements(CDH_Challenge<G> challenge) {
        if (!GroupElement.isValid(challenge.generator))
            return false;
        if (!GroupElement.isValid(challenge.x))
            return false;
        if (!GroupElement.isValid(challenge.y))
            return false;
        return true;
    }

    /**
     * In case of an error (challenge is null, ...), this
     * adversary returns null.
     * 
     * @return
     */
    protected IGroupElement getErrorAnswer() {
        return null;
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
     * that encodes
     * dlog(x) * dlog(y) / dlog(g).
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
        var new_exponent = x.multiply(y).multiply(inv_base).mod(order);
        return new GroupElement(group, new_exponent);
    }

    @Override
    public IGroupElement run(I_CDH_Challenger<IGroupElement> challenger) {
        calls++;
        if (challenger == null)
            throw new NullPointerException("The argument challenger was null!");

        CDH_Challenge<IGroupElement> challenge = challenger.getChallenge();

        if (!isNotNull(challenge))
            return getErrorAnswer();
        if (!usesCorrectGroupElements(challenge))
            return getErrorAnswer();
        return getCorrectAnswer(challenge);
    }
}
