package dlog;

import basics.IAdversary;
import genericGroups.IBasicGroupElement;

/**
 * A DLog adversary solves DLog challenges. The challenges given to this
 * adversary should be of type DLog_Challenge<G>.
 * 
 * @param G the type of group elements of the given challenge.
 * @param E the type of exponents of the generic group G.
 */
public interface I_DLog_Adversary<G extends IBasicGroupElement<G>, E> extends IAdversary<I_DLog_Challenger<G>, E> {

}
