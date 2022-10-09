package katzwang;

import java.math.BigInteger;

import basics.IAdversary;
import genericGroups.IGroupElement;

public interface I_KatzWang_EUFCMA_Adversary extends IAdversary<I_KatzWang_EUFCMA_Challenger<IGroupElement, BigInteger>, KatzWangSolution<BigInteger>>{
    /**
     * runs the adversary. The adversary may make calls to the hash and sign methods of the challenger.
     * @param challenger the challenger that the adversary may query to obtain its challenge, to sign messages, and to obtain hash values
     * @return if the adversary is successfull, it will return a valid Katz-Wang solution.
     * Otherwise it may return null or an invalid solution.
     */
    @Override
    public KatzWangSolution<BigInteger> run(I_KatzWang_EUFCMA_Challenger<IGroupElement, BigInteger> challenger);
    /**
     * Allows to reset the adversary to internally use a fixed seed.
     * If you call this method (even without calling run before or after) your reduction will not be counted as tight.
     * DO NOT CALL THIS METHOD IF YOU WANT FULL POINTS.
     * @param seed the seed that the adversary will use to make random choices
     */
    public void reset(long seed);

     /**
     * returns whether the adversary's seed has been resetted.
     * @return true if the method reset has been called, false otherwise.
     */
    public boolean hasNotBeenResetted();
}
