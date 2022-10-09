package dlog;

import java.security.SecureRandom;

import java.math.BigInteger;

import genericGroups.IGroupElement;
import utils.NumberUtils;

/**
 * A DLog challenger that uses an actual prime order group internally
 */
public class DLog_Challenger implements I_DLog_Challenger<IGroupElement> {

    private final SecureRandom rnd = new SecureRandom();
    private final DLog_Challenge<IGroupElement> challenge;
    private final BigInteger discreteLogarithm;

    public DLog_Challenger(IGroupElement generator) {

        var order = generator.getGroupOrder();
        this.discreteLogarithm = NumberUtils.getRandomBigInteger(rnd, order);
        var X = generator.power(discreteLogarithm);
        this.challenge = new DLog_Challenge<IGroupElement>(generator, X);
    }

    @Override
    public DLog_Challenge<IGroupElement> getChallenge() {
        return challenge;
    }

    @Override
    public boolean checkSolution(BigInteger exponent) {
        //ToDo: was wenn exponent ein Derivat von BigInteger ist?
        if (exponent == null)
            return false;
        var h = this.challenge.generator.power(exponent);
        return h.equals(this.challenge.x);
    }
}
