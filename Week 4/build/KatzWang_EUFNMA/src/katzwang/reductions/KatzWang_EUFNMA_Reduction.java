package katzwang.reductions;

import java.math.BigInteger;

import ddh.I_DDH_Challenger;
import genericGroups.IGroupElement;
import katzwang.A_KatzWang_EUFNMA_Adversary;
import katzwang.KatzWangPK;
import utils.Triple;

public class KatzWang_EUFNMA_Reduction extends A_KatzWang_EUFNMA_Reduction {

    public KatzWang_EUFNMA_Reduction(A_KatzWang_EUFNMA_Adversary adversary) {
        super(adversary);
        // Do not change this constructor!
    }

    @Override
    public Boolean run(I_DDH_Challenger<IGroupElement, BigInteger> challenger) {
        // Write your Code here!

        // You can use the Triple class...
        var triple = new Triple<Integer, Integer, Integer>(1, 2, 3);

        return null;
    }

    @Override
    public KatzWangPK<IGroupElement> getChallenge() {
        // Write your Code here!
        return null;
    }

    @Override
    public BigInteger hash(IGroupElement comm1, IGroupElement comm2, String message) {
        // Write your Code here!
        return null;
    }

}
