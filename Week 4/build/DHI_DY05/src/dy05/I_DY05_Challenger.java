package dy05;


import basics.*;
import genericGroups.IGroupElement;

public interface I_DY05_Challenger extends IChallenger {
    public DY05_PK getPK();

    public void receiveChallengePreimage(int challenge_preimage) throws Exception;

    public IGroupElement eval(int preimage);

    // public int getMessageModulus();
}
