package dlog_cdh;

import basics.IReduction;
import cdh.I_CDH_Adversary;
import cdh.I_CDH_Challenger;
import dlog.I_DLog_Adversary;
import dlog.I_DLog_Challenger;
import genericGroups.IBasicGroupElement;

/**
 * The interface for you solution. This interface adds an additional method
 * ({@code setAdversary}) which will be used by the TestRunner to provide you
 * with an adversary for the CDH assumption.
 * 
 * @param G the type of group elements of the given challenge. Ideally, G equals
 *          IGroupElement.
 * @param E the type of exponents of the group elements of type G. Ideally, E equals IRandomVariable.
 */
public interface I_DLog_CDH_Reduction<G extends IBasicGroupElement<G>, E> extends
                IReduction<I_DLog_Challenger<G>, E>, I_CDH_Challenger<G>, I_DLog_Adversary<G, E> {
        /**
         * The TestRunner will use this method to give you an adversary for solving CDH
         * challenges.
         * 
         * @param adversary The adversary which you need to use to solve the DLog
         *                  challenge. In this method, you should store the adversary.
         */
        void setAdversary(I_CDH_Adversary<G> adversary);
}
