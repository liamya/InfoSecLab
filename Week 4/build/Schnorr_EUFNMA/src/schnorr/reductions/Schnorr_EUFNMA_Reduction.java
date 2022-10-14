package schnorr.reductions;

import java.math.BigInteger;
import java.util.HashMap;
import java.util.Random;

import dlog.DLog_Challenge;
import dlog.I_DLog_Challenger;
import genericGroups.IGroupElement;
import schnorr.I_Schnorr_EUFNMA_Adversary;
import schnorr.SchnorrSolution;
import schnorr.Schnorr_PK;
import utils.NumberUtils;
import utils.Pair;

public class Schnorr_EUFNMA_Reduction extends A_Schnorr_EUFNMA_Reduction{

    HashMap<IGroupElement, HashMap<String, BigInteger>> map = new HashMap<IGroupElement, HashMap<String, BigInteger>>();

    private IGroupElement public_key;
    private IGroupElement base;

    public Schnorr_EUFNMA_Reduction(I_Schnorr_EUFNMA_Adversary<IGroupElement, BigInteger> adversary) {
        super(adversary);
        //Do not change this constructor!
    }

    @Override
    public Schnorr_PK<IGroupElement> getChallenge() {
        //Write your Code here!
        return new Schnorr_PK<IGroupElement>(base, public_key);
    }

    @Override
    public BigInteger hash(String message, IGroupElement r) {
        //Write your Code here!
        
        if(!map.containsKey(r)){
            map.put(r, new HashMap<String, BigInteger>());
        }
       
        if(map.get(r).containsKey(message)){
            return map.get(r).get(message);
        } else {
            BigInteger p = r.getGroupOrder();
            BigInteger max = p.subtract(BigInteger.ONE); // between 0 and p-1
            Random random = new Random();
            BigInteger newValue = NumberUtils.getRandomBigInteger(random, max);
            map.get(r).put(message, newValue);
            return newValue;
        }
        /*BigInteger p = r.getGroupOrder();
        BigInteger max = p.subtract(BigInteger.ONE); // between 0 and p-1
        Random random = new Random();
        BigInteger newValue = NumberUtils.getRandomBigInteger(random, max);
        return newValue;*/
    }

    @Override
    public BigInteger run(I_DLog_Challenger<IGroupElement> challenger) {
        //Write your Code here!

        // You can use the Triple class...
        //var pair = new Pair<Integer, Integer>(1, 2);
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
        map = new HashMap<IGroupElement, HashMap<String, BigInteger>>();
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
            // TODO: handle exception
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
