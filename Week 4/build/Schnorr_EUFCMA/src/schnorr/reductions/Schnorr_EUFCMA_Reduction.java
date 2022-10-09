package schnorr.reductions;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Random;

import dlog.DLog_Challenge;
import dlog.I_DLog_Challenger;
import genericGroups.IGroupElement;
import schnorr.I_Schnorr_EUFCMA_Adversary;
import schnorr.SchnorrSignature;
import schnorr.SchnorrSolution;
import schnorr.Schnorr_PK;
import utils.NumberUtils;
import utils.Pair;

public class Schnorr_EUFCMA_Reduction extends A_Schnorr_EUFCMA_Reduction {

    public Schnorr_EUFCMA_Reduction(I_Schnorr_EUFCMA_Adversary<IGroupElement, BigInteger> adversary) {
        super(adversary);
        // Do not change this constructor!
    }

    @Override
    public Schnorr_PK<IGroupElement> getChallenge() {
        // Implement your code here!
        return null;
    }

    @Override
    public SchnorrSignature<BigInteger> sign(String message) {
        // Implement your code here!
        return null;
    }

    @Override
    public BigInteger hash(String message, IGroupElement r) {
        // Implement your code here!
        return null;
    }

    @Override
    public BigInteger run(I_DLog_Challenger<IGroupElement> challenger) {
        // Implement your code here!
        return null;
    }
}
