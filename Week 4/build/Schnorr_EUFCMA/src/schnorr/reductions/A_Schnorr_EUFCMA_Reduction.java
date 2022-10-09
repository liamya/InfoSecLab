package schnorr.reductions;

import java.math.BigInteger;

import genericGroups.IGroupElement;
import schnorr.I_Schnorr_EUFCMA_Adversary;
import schnorr.I_Schnorr_EUFCMA_Challenger;

public abstract class A_Schnorr_EUFCMA_Reduction
        extends A_Schnorr_EUF_Reduction<I_Schnorr_EUFCMA_Adversary<IGroupElement, BigInteger>>
        implements I_Schnorr_EUFCMA_Challenger<IGroupElement, BigInteger> {

    public A_Schnorr_EUFCMA_Reduction(I_Schnorr_EUFCMA_Adversary<IGroupElement, BigInteger> adversary) {
        super(adversary);
    }

}
