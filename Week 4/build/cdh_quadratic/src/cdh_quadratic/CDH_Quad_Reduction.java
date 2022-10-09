package cdh_quadratic;

import java.math.BigInteger;
import cdh.CDH_Challenge;
import cdh.I_CDH_Challenger;
import genericGroups.IGroupElement;

/**
 * This is the file you need to implement.
 * 
 * Implement the methods {@code run} and {@code getChallenge} of this class.
 * Do not change the constructor of this class.
 */
public class CDH_Quad_Reduction extends A_CDH_Quad_Reduction<IGroupElement> {

    /**
     * Do NOT change or remove this constructor. When your reduction can not provide
     * a working standard constructor, the TestRunner will not be able to test your
     * code and you will get zero points.
     */
    public CDH_Quad_Reduction() {
        // Do not add any code here!
    }

    @Override
    public IGroupElement run(I_CDH_Challenger<IGroupElement> challenger) {
        // This is one of the both methods you need to implement.

        // By the following call you will receive a DLog challenge.
        CDH_Challenge<IGroupElement> challenge = challenger.getChallenge();

        // your reduction does not need to be tight. I.e., you may call
        // adversary.run(this) multiple times.

        // Remember that this is a group of prime order p.
        // In particular, we have a^(p-1) = 1 mod p for each a != 0.

        return null;
    }

    @Override
    public CDH_Challenge<IGroupElement> getChallenge() {

        // This is the second method you need to implement.
        // You need to create a CDH challenge here which will be given to your CDH
        // adversary.
        IGroupElement generator = null;
        IGroupElement x = null;
        IGroupElement y = null;
        // Instead of null, your cdh challenge should consist of meaningful group
        // elements.
        CDH_Challenge<IGroupElement> cdh_challenge = new CDH_Challenge<IGroupElement>(generator, x, y);

        return cdh_challenge;
    }
}
