package dlog_cdh;

import cdh.I_CDH_Adversary;
import genericGroups.IBasicGroupElement;

/**
 * For your convenience, this class implements the {@code setAdversary} method
 * for you and has a field ({@code adversary}) in which it will store the CDH
 * adversary you get by the TestRunner.
 * 
 * @author Julia
 **/
public abstract class A_DLog_CDH_Reduction<G extends IBasicGroupElement<G>, E>
        implements I_DLog_CDH_Reduction<G, E> {
    /**
     * A CDH adversary to help you with solving your challenge.
     */
    protected I_CDH_Adversary<G> adversary;

    @Override
    public void setAdversary(I_CDH_Adversary<G> adversary) {
        this.adversary = adversary;
    }
}
