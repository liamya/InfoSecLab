package rsapkcs;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Random;

import static utils.NumberUtils.getRandomBigInteger;
import static utils.NumberUtils.ceilDivide;
import static utils.NumberUtils.getCeilLog;

public class RSAPKCS_OWCL_Adversary implements I_RSAPKCS_OWCL_Adversary {
    public RSAPKCS_OWCL_Adversary() {
        // Do not change this constructor!
    }

    /*
     * @see basics.IAdversary#run(basics.IChallenger)
     */
    @Override
    public BigInteger run(final I_RSAPKCS_OWCL_Challenger challenger) {
        // Write code here!
        return BigInteger.ZERO;
    }
}