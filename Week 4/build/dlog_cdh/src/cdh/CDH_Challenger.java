package cdh;

import java.security.SecureRandom;

import java.math.BigInteger;

import genericGroups.GroupElement;
import genericGroups.IGroupElement;
import utils.NumberUtils;

/**
 * A CDH challenger that uses an actual prime order group internally
 */
public class CDH_Challenger implements I_CDH_Challenger<IGroupElement> {

    private final SecureRandom rnd = new SecureRandom();
    private final CDH_Challenge<IGroupElement> challenge;
    private final BigInteger x;
    private final BigInteger y;

    public CDH_Challenger(IGroupElement generator) {

        var order = generator.getGroupOrder();
        this.x = NumberUtils.getRandomBigInteger(rnd, order);
        this.y = NumberUtils.getRandomBigInteger(rnd, order);
        var gX = generator.power(x);
        var gY = generator.power(y);
        this.challenge = new CDH_Challenge<IGroupElement>(generator, gX, gY);
    }

    @Override
    public CDH_Challenge<IGroupElement> getChallenge() {
        return challenge;
    }

    /**
     * Returns true if gXY is a correct solution to the challenge of this
     * challenger.
     * 
     * @param gXY the solution returned by the reduction of the student.
     * @return true iff gXY == (gX)^y.
     */
    public boolean checkSolution(IGroupElement gXY) {
        if (!GroupElement.isValid(gXY))
            return false;
        var h = this.challenge.x.power(y);
        return h.equals(gXY);
    }
}
