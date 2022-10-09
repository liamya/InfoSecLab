package katzwang.reductions;

import java.math.BigInteger;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Random;
import java.util.Set;

import ddh.DDH_Challenge;
import ddh.I_DDH_Challenger;
import genericGroups.IGroupElement;
import katzwang.A_KatzWang_EUFCMA_Adversary;
import katzwang.KatzWangPK;
import katzwang.KatzWangSignature;
import katzwang.KatzWangSolution;
import utils.NumberUtils;
import utils.Triple;

public class KatzWang_EUFCMA_Reduction extends A_KatzWang_EUFCMA_Reduction {

    public KatzWang_EUFCMA_Reduction(A_KatzWang_EUFCMA_Adversary adversary) {
        super(adversary);
        // Do not change this constructor
    }

    @Override
    public Boolean run(I_DDH_Challenger<IGroupElement, BigInteger> challenger) {
        // Implement your code here!
        return false;
    }

    @Override
    public KatzWangPK<IGroupElement> getChallenge() {
        // Implement your code here!
        return null;
    }

    @Override
    public BigInteger hash(IGroupElement comm1, IGroupElement comm2, String message) {
        // Implement your code here!
        return BigInteger.ZERO;
    }

    @Override
    public KatzWangSignature<BigInteger> sign(String message) {
        // Implement your code here!
        return null;
    }
}
