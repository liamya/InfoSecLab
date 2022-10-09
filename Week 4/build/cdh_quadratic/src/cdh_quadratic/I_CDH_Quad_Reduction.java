package cdh_quadratic;

import basics.IReduction;
import cdh.I_CDH_Adversary;
import cdh.I_CDH_Challenger;
import genericGroups.IBasicGroupElement;

/**
 * The interface for you solution. This interface adds an additional method
 * ({@code setAdversary}) which will be used by the TestRunner to provide you
 * with a quadratic adversary.
 * 
 * @param G the type of group elements of the given challenge. Ideally, G equals
 *          IGroupElement.
 */
public interface I_CDH_Quad_Reduction<G extends IBasicGroupElement<G>> extends
                IReduction<I_CDH_Challenger<G>, G>, I_CDH_Challenger<G>, I_Quadratic_Adversary<G> {
        /**
         * The TestRunner will use this method to give you a quadratic adversary.
         * 
         * @param adversary The adversary which you need to use to solve the CDH
         *                  challenge. In this method, you should store the adversary.
         */
        void setAdversary(I_Quadratic_Adversary<G> adversary);
}
