package cdh;

import basics.IChallenger;

/**
 * A CDH challenger provides CDH challenges and plays the security game of the
 * CDH assumption with implementations of the {@code I_CDH_Adversary} interface.
 * It has a method {@code getChallenge()} that will be called by a CDH
 * adversary and which provides the CDH challenge in the corresponding security
 * game.
 * 
 * @param G the type of group elements of the given challenge.
 */
public interface I_CDH_Challenger<G> extends IChallenger {
    /**
     * Returns the challenge of this challenger. This method should always return
     * the same challenge, no matter how often it has been called.
     * 
     * @return the challenge of this challenger.
     */
    CDH_Challenge<G> getChallenge();
}
