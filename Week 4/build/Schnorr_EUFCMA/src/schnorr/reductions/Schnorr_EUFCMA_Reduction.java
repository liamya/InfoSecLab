package schnorr.reductions;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.HashMap;

import dlog.DLog_Challenge;
import dlog.I_DLog_Challenger;
import genericGroups.GroupElement;
import genericGroups.IGroupElement;
import schnorr.I_Schnorr_EUFCMA_Adversary;
import schnorr.SchnorrSignature;
import schnorr.SchnorrSolution;
import schnorr.Schnorr_PK;
import utils.NumberUtils;
import utils.Pair;

public class Schnorr_EUFCMA_Reduction extends A_Schnorr_EUFCMA_Reduction {

    HashMap<Pair<String, IGroupElement>, BigInteger> map = new HashMap<Pair<String, IGroupElement>, BigInteger>();

    private IGroupElement public_key; // y = g^x
    private IGroupElement base; // g

    public Schnorr_EUFCMA_Reduction(I_Schnorr_EUFCMA_Adversary<IGroupElement, BigInteger> adversary) {
        super(adversary);
        // Do not change this constructor!
    }

    @Override
    public Schnorr_PK<IGroupElement> getChallenge() {
        // Implement your code here!
        return new Schnorr_PK<IGroupElement>(base, public_key);
    }

    @Override
    public SchnorrSignature<BigInteger> sign(String message) {
        
        // Implement your code here!
        BigInteger p = base.getGroupOrder();
        BigInteger max = p.subtract(BigInteger.ONE); // between 0 and p-1
        SecureRandom random = new SecureRandom();
        BigInteger c = NumberUtils.getRandomBigInteger(random, max);
        BigInteger s = NumberUtils.getRandomBigInteger(random, max);
      
        IGroupElement R = base.power(s).multiply(public_key.power(c.negate()));
        var pair = new Pair<>(message, R);
        map.put(pair, c);

        // check
        
        var schnorrsignature = new SchnorrSignature<>(c, s);
        return schnorrsignature;
    }

    @Override
    public BigInteger hash(String message, IGroupElement r) {
        // Implement your code here!
        var pair = new Pair<>(message, r);
       
        if(map.containsKey(pair)){
            return map.get(pair);
        } else {
            BigInteger p = r.getGroupOrder();
            BigInteger max = p.subtract(BigInteger.ONE); // between 0 and p-1
            SecureRandom random = new SecureRandom();
            BigInteger newValue = NumberUtils.getRandomBigInteger(random, max);
            map.put(pair, newValue);
            return newValue;
        }
    }

    @Override
    public BigInteger run(I_DLog_Challenger<IGroupElement> challenger) {
        // Implement your code here!
        DLog_Challenge<IGroupElement> challenge = challenger.getChallenge();

        base = challenge.generator;
        BigInteger q = challenge.generator.getGroupOrder();
        public_key = challenge.x;
        // we have to return y which comes from x = g^y
        this.adversary.reset(1);
        SchnorrSolution<BigInteger> signature = this.adversary.run(this);
        if(signature == null){
            return BigInteger.ZERO;
        }
        BigInteger c1 = signature.signature.c;
        BigInteger s1 = signature.signature.s;

        BigInteger c2 = null;
        BigInteger s2 = null;

        while(true){
        map.clear();
        this.adversary.reset(1);
        SchnorrSolution<BigInteger> signature2 = this.adversary.run(this);
        if(signature2 == null){
            return BigInteger.ZERO;
        }
        c2 = signature2.signature.c;
        s2 = signature2.signature.s;

        if(c1 != c2 && s1 != s2 && (c2 != null && c2 != null)){
            break;
        }
        }

        BigInteger x = null;
        try {
            x = (s1.subtract(s2).multiply((c1.subtract(c2).modInverse(q)))).mod(q);        // calculate solution

        } catch (Exception e) {
            System.out.println(c1.subtract(c2));
        }
       
        // check
        boolean check = challenge.generator.power(x).equals(public_key);
        if(check == false){
            System.out.println();
        }
        return x;
    }
}
