package katzwang.reductions;

import java.math.BigInteger;

import ddh.I_DDH_Adversary;
import genericGroups.IGroupElement;
import katzwang.A_KatzWang_EUFNMA_Adversary;
import katzwang.A_KatzWang_EUFNMA_Challenger;

public abstract class A_KatzWang_EUFNMA_Reduction extends A_KatzWang_EUFNMA_Challenger
        implements I_DDH_Adversary<IGroupElement, BigInteger> {

    public A_KatzWang_EUFNMA_Reduction(A_KatzWang_EUFNMA_Adversary adversary) {
        super(adversary);
    }
}
