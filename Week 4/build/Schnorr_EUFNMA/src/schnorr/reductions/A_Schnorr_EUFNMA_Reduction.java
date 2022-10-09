package schnorr.reductions;

import java.math.BigInteger;

import genericGroups.IGroupElement;
import schnorr.I_Schnorr_EUFNMA_Adversary;
import schnorr.I_Schnorr_EUFNMA_Challenger;
import schnorr.SchnorrSignature;

public abstract class A_Schnorr_EUFNMA_Reduction
        extends A_Schnorr_EUF_Reduction<I_Schnorr_EUFNMA_Adversary<IGroupElement, BigInteger>>
        implements I_Schnorr_EUFNMA_Challenger<IGroupElement, BigInteger> {
    public A_Schnorr_EUFNMA_Reduction(I_Schnorr_EUFNMA_Adversary<IGroupElement, BigInteger> adversary) {
        super(adversary);
    }

    @Override
    public SchnorrSignature<BigInteger> sign(String message) {
        return null;
    }
}
