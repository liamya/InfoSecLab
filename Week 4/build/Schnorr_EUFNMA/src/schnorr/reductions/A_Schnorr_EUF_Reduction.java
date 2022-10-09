package schnorr.reductions;

import java.math.BigInteger;

import dlog.I_DLog_Adversary;
import genericGroups.IGroupElement;
import schnorr.I_Schnorr_EUF_Adversary;
import schnorr.I_Schnorr_EUF_Challenger;

public abstract class A_Schnorr_EUF_Reduction<A extends I_Schnorr_EUF_Adversary<IGroupElement, BigInteger>>
        implements I_DLog_Adversary<IGroupElement, BigInteger>, I_Schnorr_EUF_Challenger<IGroupElement, BigInteger> {
    protected A adversary;

    public A_Schnorr_EUF_Reduction(A adversary) {
        this.adversary = adversary;
    }

    public void setAdversary(A adversary) {
        this.adversary = adversary;
    }
}
