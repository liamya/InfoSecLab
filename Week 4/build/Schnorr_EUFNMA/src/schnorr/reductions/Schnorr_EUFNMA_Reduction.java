package schnorr.reductions;

import java.math.BigInteger;

import dlog.I_DLog_Challenger;
import genericGroups.IGroupElement;
import schnorr.I_Schnorr_EUFNMA_Adversary;
import schnorr.Schnorr_PK;
import utils.Pair;

public class Schnorr_EUFNMA_Reduction extends A_Schnorr_EUFNMA_Reduction{

    public Schnorr_EUFNMA_Reduction(I_Schnorr_EUFNMA_Adversary<IGroupElement, BigInteger> adversary) {
        super(adversary);
        //Do not change this constructor!
    }

    @Override
    public Schnorr_PK<IGroupElement> getChallenge() {
        //Write your Code here!
        return null;
    }

    @Override
    public BigInteger hash(String message, IGroupElement r) {
        //Write your Code here!
        return null;
    }

    @Override
    public BigInteger run(I_DLog_Challenger<IGroupElement> challenger) {
        //Write your Code here!

        // You can use the Triple class...
        var pair = new Pair<Integer, Integer>(1, 2);

        return null;
    }
    
}
