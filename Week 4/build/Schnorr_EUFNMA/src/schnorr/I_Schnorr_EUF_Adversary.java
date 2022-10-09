package schnorr;

import basics.IAdversary;

public interface I_Schnorr_EUF_Adversary<G,E> extends IAdversary<I_Schnorr_EUF_Challenger<G,E>, SchnorrSolution<E>>{
    /**
     * this resets the adversary's internal seed to the value provided. 
     * The adversary will use this seed to derive its random choices from it. 
     * It will behave the same using this seed, provided it is given the same inputs as before
     * @param seed the seed that the adversary shall use to generate random choices
     */
    public void reset(long seed);
}
