package schnorr;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;

import dlog.DLog_Challenger;
import genericGroups.AlgebraicGroup;
import genericGroups.GroupElement;
import genericGroups.IGroupElement;
import grading.ConsoleHelper;
import grading.StudentTestRunner;
import schnorr.reductions.A_Schnorr_EUFCMA_Reduction;
import schnorr.reductions.Schnorr_EUFCMA_Reduction;

public class Schnorr_EUFCMA_TestRunner extends StudentTestRunner {
    private class TestingTuple {
        Class<? extends Schnorr_EUFCMA_Adversary> advClass;
        int numMessages;
        int n;
        int t;

        public TestingTuple(Class<? extends Schnorr_EUFCMA_Adversary> advClass,
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

    ArrayList<TestingTuple> test_cases;
    private static final Class<? extends DLog_Challenger> challengerClass = DLog_Challenger.class;
    private Class<? extends A_Schnorr_EUFCMA_Reduction> reductionClass;
    private final SecureRandom RNG = new SecureRandom();
    int groupBitLength;

    public Schnorr_EUFCMA_TestRunner(int groupBitLength,
            Class<? extends A_Schnorr_EUFCMA_Reduction> reductionClass) {
        setup(groupBitLength, reductionClass);
    }

    private void setup(int groupBitLength,
            Class<? extends A_Schnorr_EUFCMA_Reduction> reductionClass) {
        this.reductionClass = reductionClass;
        this.groupBitLength = groupBitLength;

        test_cases = new ArrayList<TestingTuple>();

        int n = 10;
        int t = 10;
        test_cases.add(new TestingTuple(Schnorr_EUFCMA_Adversary.class, 1, n, t));
        test_cases.add(new TestingTuple(Schnorr_EUFCMA_noCheck_Adversary.class, 1, n, t));

        n = 132;
        t = 1;
        test_cases.add(new TestingTuple(Schnorr_EUFCMA_hashConst_Adversary.class, 10, n, t));

    }

    @Override
    public void run() throws Exception {
        this.maxPoints = test_cases.size();
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
                ConsoleHelper.printlnGreen(System.out,
                        "Your Code passed TestCase " + i);
            System.out.println();

            if (result >= 0)
                currentPoints += result;
        }
    }

    private int runTest(TestingTuple test) throws Exception {
        int numCorrect = 0;
        for (int i = 0; i < test.n; i++) {
            AlgebraicGroup<BigInteger> group = AlgebraicGroup
                    .createGroup(BigInteger.probablePrime(groupBitLength, RNG));
            IGroupElement generator = new GroupElement(group, BigInteger.ONE);
            var challenger = challengerClass.getDeclaredConstructor(IGroupElement.class).newInstance(generator);
            var adversary = test.advClass.getDeclaredConstructor(AlgebraicGroup.class, int.class, double.class)
                    .newInstance(group, test.numMessages, 1);

            var reduction = reductionClass
                    .getDeclaredConstructor(I_Schnorr_EUFCMA_Adversary.class)
                    .newInstance(adversary);
            var solution = reduction.run(challenger);
            if (challenger.checkSolution(solution))
                numCorrect++;
        }
        if (numCorrect >= test.t)
            return 1;
        else
            return 0;
    }

    @Override
    protected void printFinishMessage() {
        stdOut.println();
        stdOut.println(disclaimerMessage);
    }

    public static void main(String[] args) {
        var testrunner = new Schnorr_EUFCMA_TestRunner(128,
                Schnorr_EUFCMA_Reduction.class);
        testrunner.execute();
    }

}
