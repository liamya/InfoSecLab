package cdh_quadratic;

import genericGroups.IBasicGroupElement;

/**
 * For your convenience, this class implements the {@code setAdversary} method
 * for you and has a field ({@code adversary}) in which it will store the
 * quadratic adversary you get by the TestRunner.
 */
public abstract class A_CDH_Quad_Reduction<G extends IBasicGroupElement<G>>
        implements I_CDH_Quad_Reduction<G> {
    /**
     * A quadratic adversary to help you with solving your challenge.
     */
    protected I_Quadratic_Adversary<G> adversary;

    @Override
    public void setAdversary(I_Quadratic_Adversary<G> adversary) {
        this.adversary = adversary;
    }
}
