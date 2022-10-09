package cdh;

import basics.IAdversary;

/**
 * A CDH adversary solves CDH challenges. The challenges given to this
 * adversary should be of type CDH_Challenge<G>.
 * 
 * @param G the type of group elements of the given challenge.
 */
public interface I_CDH_Adversary<G> extends IAdversary<I_CDH_Challenger<G>, G> {

}
