package katzwang.reductions;

import java.math.BigInteger;

import ddh.I_DDH_Adversary;
import genericGroups.IGroupElement;
import katzwang.A_KatzWang_EUFCMA_Adversary;
import katzwang.A_KatzWang_EUFCMA_Challenger;

public abstract class A_KatzWang_EUFCMA_Reduction extends A_KatzWang_EUFCMA_Challenger
        implements I_DDH_Adversary<IGroupElement, BigInteger> {
    protected A_KatzWang_EUFCMA_Adversary adversary;

    public A_KatzWang_EUFCMA_Reduction(A_KatzWang_EUFCMA_Adversary adversary) {
        this.adversary = adversary;
    }

}
