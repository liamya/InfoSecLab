package schnorr;

public interface I_Schnorr_EUFCMA_Challenger<G,E> extends I_Schnorr_EUF_Challenger<G,E>{
    @Override
    public SchnorrSignature<E> sign(String message);
}
