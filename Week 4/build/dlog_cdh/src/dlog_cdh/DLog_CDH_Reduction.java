package dlog_cdh;

import java.math.BigInteger;

import cdh.CDH_Challenge;
import dlog.DLog_Challenge;
import dlog.I_DLog_Challenger;
import genericGroups.IGroupElement;

/**
 * This is the file you need to implement.
 * 
 * Implement the method {@code run} of this class.
 * Do not change the constructor of this class.
 */
public class DLog_CDH_Reduction extends A_DLog_CDH_Reduction<IGroupElement, BigInteger> {

    /**
     * You will need this field.
     */
    private CDH_Challenge<IGroupElement> cdh_challenge;
    /**
     * Save here the group generator of the DLog challenge given to you.
     */
    private IGroupElement generator;

    /**
     * Do NOT change or remove this constructor. When your reduction can not provide
     * a working standard constructor, the TestRunner will not be able to test your
     * code and you will get zero points.
     */
    public DLog_CDH_Reduction() {
        // Do not add any code here!
    }

    @Override
    public BigInteger run(I_DLog_Challenger<IGroupElement> challenger) {
        // This is one of the both methods you need to implement.

        // By the following call you will receive a DLog challenge.
        DLog_Challenge<IGroupElement> challenge = challenger.getChallenge();
        this.generator = challenge.generator;

        // You may assume that adversary is a perfect adversary.
        // I.e., cdh_solution will always be of the form g^(x * y) when you give the
        // adversary g, g^x and g^y in the getChallenge method below.

        // your reduction does not need to be tight. I.e., you may call
        // adversary.run(this) multiple times.

        BigInteger groupOrder = challenge.generator.getGroupOrder();
        // Make use of the fact that the group order is of the form 1 + p1 * ... * pn
        // for many small primes pi !!
        int[] primes = PrimesHelper.getDecompositionOfPhi(groupOrder);
        // Also, make use of a generator of the multiplicative group mod p.
        BigInteger multiplicativeGenerator = PrimesHelper.getGenerator(groupOrder);

        // You can also use the method of CRTHelper
        int[] values = new int[primes.length];
        BigInteger composed = CRTHelper.crtCompose(values, primes);

        return BigInteger.ZERO;
    }

    @Override
    public CDH_Challenge<IGroupElement> getChallenge() {
        // There is not really a reason to change any of the code of this method.
        return cdh_challenge;
    }

    /**
     * For your own convenience, you should write a cdh method for yourself that,
     * when given group elements g^x and g^y, returns a group element g^(x*y)
     * (where g is the generator from the DLog challenge).
     */
    private IGroupElement cdh(IGroupElement x, IGroupElement y) {
        // Use the run method of your CDH adversary to have it solve CDH-challenges:
        IGroupElement cdh_solution = adversary.run(this);
        // You should specify the challenge in the cdh_challenge field of this class.
        // So, the above getChallenge method returns the correct cdh challenge to
        // adversary.
        return null;
    }

    /**
     * For your own convenience, you should write a cdh_power method for yourself
     * that,
     * when given a group element g^x and a number k, returns a group element
     * g^(x^k) (where g is the generator from the DLog challenge).
     */
    private IGroupElement cdh_power(IGroupElement x, BigInteger exponent) {
        // For this method, use your cdh method and think of aritmetic algorithms for
        // fast exponentiation.
        // Use the methods exponent.bitLength() and exponent.testBit(n)!
        return null;
    }
}
