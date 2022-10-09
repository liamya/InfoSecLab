package schemes;

import java.lang.reflect.InvocationTargetException;
import java.util.ArrayList;
import java.util.List;

import grading.ConsoleHelper;
import grading.StudentTestRunner;
import rsapkcs.I_RSAPKCS_OWCL_Adversary;
import rsapkcs.I_RSAPKCS_OWCL_Challenger;
import rsapkcs.RSAPKCS_OWCL_Adversary;

public class Bleichenbacher_TestRunner extends StudentTestRunner {
    private class TestingTuple {
        Class<? extends RSAPKCS_OWCL_Challenger> challenger;
        Class<? extends I_RSAPKCS_OWCL_Adversary> adversary;

        TestingTuple(final Class<? extends RSAPKCS_OWCL_Challenger> challenger,
                final Class<? extends I_RSAPKCS_OWCL_Adversary> adversary) {
            this.challenger = challenger;
            this.adversary = adversary;
        }
    }

    protected static int bitLength = 70; // 46;
    protected static int queryQuota = (int) 1e7; // 10 million queries should suffice
    protected int repetitions;
    protected List<TestingTuple> test_cases;

    public Bleichenbacher_TestRunner(final Class<? extends I_RSAPKCS_OWCL_Adversary> adversaryClass,
            final int repetitions) {
        setup(adversaryClass, repetitions);
    }

    private void setup(final Class<? extends I_RSAPKCS_OWCL_Adversary> adversaryClass, final int repetitions) {
        test_cases = new ArrayList<TestingTuple>();
        this.repetitions = repetitions;

        test_cases.add(new TestingTuple(RSAPKCS_OWCL_Challenger.class,
                adversaryClass));
    }

    @Override
    public void run() throws Exception {
        maxPoints = repetitions;
        currentPoints = 0;
        preliminaryMaxPoints = 1.0;
        for (final var t : test_cases) {
            // System.out.println("testing " + t.adversary.getName());
            final double score = runTest(t);
            currentPoints += score;
        }
    }

    double runTest(final TestingTuple tuple)
            throws InstantiationException, IllegalAccessException, IllegalArgumentException,
            InvocationTargetException, NoSuchMethodException, SecurityException {
        double wins = 0;
        for (int i = 1; i <= repetitions; i++) {
            boolean didWin = false;
            final var challenger = tuple.challenger.getDeclaredConstructor(int.class, int.class)
                    .newInstance(bitLength, queryQuota);

            System.out.println("Starting Test " + i);
            final var startTime = System.currentTimeMillis();

            final var adversary = tuple.adversary.getDeclaredConstructor().newInstance();
            try {
                final var solution = adversary.run((I_RSAPKCS_OWCL_Challenger) challenger);
                didWin = challenger.testSolution(solution);
            } catch (final Exception e) {
                e.printStackTrace();
            }

            final var endTime = System.currentTimeMillis();
            final var period = endTime - startTime;
            System.out.println("Finishing Test " + i);
            System.out.println("Adversary made " + challenger.getQueryCounter() + " queries");
            System.out.println("Adversary took " + (period / 1000.0) + " seconds");
            if (didWin) {
                ConsoleHelper.printlnGreen(System.out, "Your code succeeded");
                wins++;
            } else
                ConsoleHelper.printlnRed(System.out, "Your code failed");
            System.out.println();

            // System.out.println("r: " + i);
            // System.out.println("q: " + challenger.getQueryCounter());
            // System.out.println("t: " + period);
            // System.out.println("d: " + (period * 1.0 / challenger.getQueryCounter()));
        }
        return wins;
    }

    @Override
    protected void printFinishMessage() {
        int a = (int)Math.round(currentPoints);
        if (a > 0)
            ConsoleHelper.printlnGreen(System.out, "Your code succeded in " + a + " of " + repetitions + " tests");
        else 
        ConsoleHelper.printlnRed(System.out, "Your code failed each of the " + repetitions + " tests");
        stdOut.println();
        stdOut.println(disclaimerMessage);
    }

    public static void main(final String[] args) {
        final var test = new Bleichenbacher_TestRunner(RSAPKCS_OWCL_Adversary.class, 6);
        test.execute();
    }
}
