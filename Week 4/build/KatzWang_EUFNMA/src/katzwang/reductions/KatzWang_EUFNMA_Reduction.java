package katzwang.reductions;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.util.HashMap;
import java.util.Random;

import ddh.I_DDH_Challenger;
import genericGroups.IGroupElement;
import katzwang.A_KatzWang_EUFNMA_Adversary;
import katzwang.KatzWangPK;
import katzwang.KatzWangSolution;
import utils.NumberUtils;
import utils.Triple;

public class KatzWang_EUFNMA_Reduction extends A_KatzWang_EUFNMA_Reduction {
    private IGroupElement y2 = null;
    private IGroupElement y1 = null;
    private IGroupElement g = null;
    private IGroupElement h = null;

    HashMap<Triple<IGroupElement, IGroupElement, String>, BigInteger> map = new HashMap<Triple<IGroupElement, IGroupElement, String>, BigInteger>();

    public KatzWang_EUFNMA_Reduction(A_KatzWang_EUFNMA_Adversary adversary) {
        super(adversary);
        // Do not change this constructor!
    }

    @Override
    public Boolean run(I_DDH_Challenger<IGroupElement, BigInteger> challenger) {
        // Write your Code here!

        // You can use the Triple class...
        //var triple = new Triple<Integer, Integer, Integer>(1, 2, 3);
        var challenge = challenger.getChallenge();
        BigInteger q = challenge.generator.getGroupOrder();
        this.g = challenge.generator;
        this.h = challenge.x;
        this.y1 = challenge.y;
        this.y2 = challenge.z;

        KatzWangSolution<BigInteger> sol1 = this.adversary.run(this);
        if(sol1 == null){
            return false;
        }
        BigInteger c1 = sol1.signature.c;
        BigInteger s1 = sol1.signature.s;
        //var triple = new Triple<>(g.power(s1).multiply(this.y1.power(c1.negate())), h.power(s1).multiply(this.y2.power(c1.negate())), sol1.message);
        var A = g.power(s1).multiply(this.y1.power(c1.negate()));
        var B = h.power(s1).multiply(this.y2.power(c1.negate()));
        
        var c_check = hash(A,B, sol1.message);
        boolean check = (c1 == c_check);
        // solution has message and signaturex
        return check;
    }

    @Override
    public KatzWangPK<IGroupElement> getChallenge() {
        // Write your Code here!
        var pk = new KatzWangPK<IGroupElement>(this.g, this.h, this.y1, this.y2);
        return pk;
    }

    @Override
    public BigInteger hash(IGroupElement comm1, IGroupElement comm2, String message) {
        var triple = new Triple<>(comm1, comm1, message);

       
        if(map.containsKey(triple)){
            return map.get(triple);
        } else {
            BigInteger p = this.g.getGroupOrder();
            BigInteger max = p.subtract(BigInteger.ONE); // between 0 and p-1
            Random random = new Random();
            BigInteger newValue = NumberUtils.getRandomBigInteger(random, max);
            map.put(triple, newValue);
            return newValue;
        }

    }

}
