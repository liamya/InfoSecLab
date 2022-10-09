package schemes;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;

import ddh.DDH_Challenger;
import genericGroups.AlgebraicGroup;
import genericGroups.GroupElement;
import genericGroups.IGroupElement;
import grading.ConsoleHelper;
import grading.StudentTestRunner;
import katzwang.A_KatzWang_EUFNMA_Adversary;
import katzwang.KatzWang_EUFNMA_Adversary;
import katzwang.KatzWang_EUFNMA_hashConst_Adversary;
import katzwang.reductions.A_KatzWang_EUFNMA_Reduction;
import katzwang.reductions.KatzWang_EUFNMA_Reduction;

public class KatzWang_EUFNMA_TestRunner extends StudentTestRunner {
    private class TestingTuple {
        Class<? extends A_KatzWang_EUFNMA_Adversary> advClass;
        int numMessages;
        int n;
        int t;

        public TestingTuple(Class<? extends A_KatzWang_EUFNMA_Adversary> advClass,
                int numMessages,
                int n, int t) {
            this.advClass = advClass;
            this.numMessages = numMessages;
            this.n = n;
            this.t = t;
        }

        @Override
        public String toString() {
            String ret = "";
            ret = " Adversary: " + advClass.getName()
                    + " numMess: " + numMessages
                    + " t/n: " + t + " / " + n;
            return ret;
        }
    }

    private ArrayList<TestingTuple> test_cases;
    private Class<? extends A_KatzWang_EUFNMA_Reduction> reductionClass;
    private final SecureRandom RNG = new SecureRandom();
    private int groupBitLength;
    private Class<? extends DDH_Challenger> challengerClass = DDH_Challenger.class;

    public KatzWang_EUFNMA_TestRunner(int groupBitLength,
            Class<? extends A_KatzWang_EUFNMA_Reduction> reductionClass) {
        super();
        setup(groupBitLength, reductionClass);
    }

    private void setup(int groupBitLength,
            Class<? extends A_KatzWang_EUFNMA_Reduction> reductionClass) {
        this.reductionClass = reductionClass;
        this.groupBitLength = groupBitLength;

        int n = 100;
        int t = 100;

        test_cases = new ArrayList<TestingTuple>();
        test_cases.add(new TestingTuple(KatzWang_EUFNMA_Adversary.class,
                1, n, t));
        test_cases.add(new TestingTuple(KatzWang_EUFNMA_hashConst_Adversary.class,
                10, n, t));

        n = 332;
        t = 210;

        test_cases.add(new TestingTuple(KatzWang_EUFNMA_Adversary.class,
                1, n, t));
        test_cases.add(new TestingTuple(KatzWang_EUFNMA_hashConst_Adversary.class,
                10, n, t));
    }

    @Override
    public void run() throws Exception {
        this.maxPoints = 2 * test_cases.size();
        this.preliminaryMaxPoints = 1;
        this.currentPoints = 0;
        for (int i = 1; i <= test_cases.size(); i++) {
            var testCase = test_cases.get(i - 1);

            System.out.println("Starting TestCase " + i + " (" + testCase.n + " Tests)");
            int result = -1;
            try {
                result = runTest(testCase);
            } catch (Exception e) {
                ConsoleHelper.printlnRed(System.out, "Your code threw an exception!");
                ConsoleHelper.printlnRed(System.out,
                        "This testCase will be stopped and the exception will be printed!");
                e.printStackTrace();
            }
            System.out.println("Finished TestCase " + i);
            System.out.println();
            if (result == 0)
                ConsoleHelper.printlnRed(System.out, "Your Code failed in TestCase " + i);
            else if (result == 1)
                ConsoleHelper.printlnYellow(System.out,
                        "Your Code passed TestCase " + i + ", but resetted the adversary");
            else if (result == 2)
                ConsoleHelper.printlnGreen(System.out,
                        "Your Code passed TestCase " + i + " without resetting the adversary");
            System.out.println();

            if (result >= 0)
                currentPoints += result;
        }

    }

    /**
     * Returns the exponent of g.
     * 
     * @param group
     * @param g
     * @return
     */
    private BigInteger dlog(AlgebraicGroup<BigInteger> group, IGroupElement g) {
        return group.decode(((GroupElement) g).groupElement.handle);
    }

    /**
     * Decides the challenge of challenger.
     * Asks first challenger for his challenge (g, g^x,g^y,g^z) and then returns
     * true iff x * y = z mod p.
     * 
     * @param group
     * @param challenger
     * @return
     */
    private boolean getSolution(AlgebraicGroup<BigInteger> group, DDH_Challenger challenger) {
        var challenge = challenger.getChallenge();
        var p = group.ring.characteristic();
        var one = dlog(group, challenge.generator);
        var x = dlog(group, challenge.x);
        var y = dlog(group, challenge.y);
        var z = dlog(group, challenge.z);
        var xyMinusZ = x.multiply(y).subtract(one.multiply(z));
        var modP = xyMinusZ.mod(p);
        return modP.signum() == 0;
    }

    private int runTest(TestingTuple test) throws Exception {
        int numCorrect = 0;
        int numTight = 0;
        for (int i = 0; i < test.n; i++) {
            AlgebraicGroup<BigInteger> group = AlgebraicGroup
                    .createGroup(BigInteger.probablePrime(groupBitLength, RNG));
            IGroupElement generator = new GroupElement(group, BigInteger.ONE);
            var challenger = challengerClass.getDeclaredConstructor(IGroupElement.class).newInstance(generator);
            var adversary = test.advClass.getDeclaredConstructor(AlgebraicGroup.class, int.class, double.class)
                    .newInstance(group, test.numMessages, 1);

            boolean didWin = false;
            boolean wasTight = true;

            var reduction = reductionClass
                    .getDeclaredConstructor(A_KatzWang_EUFNMA_Adversary.class)
                    .newInstance(adversary);
            var solution = reduction.run(challenger);
            didWin = solution != null && solution == getSolution(group, challenger);
            if (didWin)
                wasTight = adversary.hasNotBeenResetted();

            if (didWin) {
                numCorrect++;
                if (wasTight)
                    numTight++;
            }
        }

        int finalScore = 0;
        if (numCorrect >= test.t) {
            finalScore++;
            if (numCorrect == numTight)
                finalScore++;
        }
        return finalScore;

    }

    @Override
    protected void printFinishMessage() {
        stdOut.println();
        stdOut.println(disclaimerMessage);
    }

    public static void main(String[] args) {
        var testrunner = new KatzWang_EUFNMA_TestRunner(128, KatzWang_EUFNMA_Reduction.class);
        testrunner.execute();
    }
}
