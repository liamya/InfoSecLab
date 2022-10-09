package dlog;

import java.math.BigInteger;

import basics.IChallenger;
import genericGroups.IBasicGroupElement;

/**
 * A DLog challenger provides DLog challenges and plays the security game of the
 * DLog assumption with implementations of the {@code I_DLog_Adversary} interface.
 * It has a method {@code getChallenge()} that will be called by a DLog
 * adversary and which provides the DLog challenge in the corresponding security
 * game.
 * 
 * @param G the type of group elements of the given challenge.
 */
public interface I_DLog_Challenger<G extends IBasicGroupElement<G>> extends IChallenger {
    /**
     * Returns the challenge of this challenger. This method should always return
     * the same challenge, no matter how often it has been called.
     * 
     * @return the challenge of this challenger.
     */
    DLog_Challenge<G> getChallenge();
    /**
     * Returns true iff g^exponent is equal to g^x.
     * 
     * @param exponent the exponent returned by the reduction.
     * @return true iff exponent is a correct solution.
     */
    boolean checkSolution(BigInteger exponent);
}
