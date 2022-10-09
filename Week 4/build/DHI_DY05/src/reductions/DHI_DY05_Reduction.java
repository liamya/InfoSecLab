package reductions;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import algebra.SimplePolynomial;
import dhi.DHI_Challenge;
import dhi.I_DHI_Challenger;
import dy05.DY05_PK;
import dy05.I_Selective_DY05_Adversary;
import genericGroups.IGroupElement;

public class DHI_DY05_Reduction implements I_DHI_DY05_Reduction {
    // Do not remove this field!
    private final I_Selective_DY05_Adversary adversary;

    public DHI_DY05_Reduction(I_Selective_DY05_Adversary adversary) {
        // Do not change this constructor!
        this.adversary = adversary;
    }

    @Override
    public IGroupElement run(I_DHI_Challenger challenger) {
        // Write Code here!

        var challenge = challenger.getChallenge();
        var generator = challenge.get(0);
        var order = generator.getGroupOrder();

        //You can use the SimplePolynomial class to solve this task
        var f = new SimplePolynomial(order, 1 ,1);

        return null;
    }

    @Override
    public void receiveChallengePreimage(int _challenge_preimage) throws Exception {
        // Write Code here!
    }

    @Override
    public IGroupElement eval(int preimage) {
        // Write Code here!
        return null;
    }

    @Override
    public DY05_PK getPK() {
        // Write Code here!
        return null;
    }
}
