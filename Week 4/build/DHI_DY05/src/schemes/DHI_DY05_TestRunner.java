package schemes;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

import dy05.I_Selective_DY05_Adversary;
import genericGroups.AlgebraicGroup;
import grading.ConsoleHelper;
import grading.StudentTestRunner;
import reductions.DHI_DY05_Reduction;
import reductions.I_DHI_DY05_Reduction;

public class DHI_DY05_TestRunner extends StudentTestRunner {
    private class TestingTuple {
        Class<? extends DHI_Challenger> challenger;
        Class<? extends I_Selective_DY05_Adversary> adversary;
        double lowerbound;
        double upperbound;

        TestingTuple(final Class<? extends DHI_Challenger> challenger,
                final Class<? extends I_Selective_DY05_Adversary> adversary,
                final double lowerbound, final double upperbound) {
            this.challenger = challenger;
            this.adversary = adversary;
            this.lowerbound = lowerbound;
            this.upperbound = upperbound;
        }

        boolean isWithinBounds(final double value) {
            return ((value >= lowerbound) && (value <= upperbound));
        }
    }

    protected static int bitLength = 128; // 46;
    protected int repetitions;
    protected List<TestingTuple> test_cases = new ArrayList<TestingTuple>();
    protected Class<? extends I_DHI_DY05_Reduction> reductionClass;
    // q = message_space_size
    private final int q = 20;
    private final SecureRandom RNG = new SecureRandom();

    public DHI_DY05_TestRunner(final Class<? extends I_DHI_DY05_Reduction> reductionClass,
            final int repetitions) {
        this.reductionClass = reductionClass;
        setup(repetitions);
    }

    private void setup(final int repetitions) {
        this.repetitions = repetitions;

        test_cases.add(new TestingTuple(DHI_Challenger.class,
                Benevolent_Selective_DY05_Adversary.class, 0.99, 1));
    }

    @Override
    public void run() throws Exception {
        this.preliminaryMaxPoints = 1;
        this.maxPoints = repetitions;

        for (final var t : test_cases) {
            currentPoints += runTest(t);
        }
    }

    double runTest(final TestingTuple tuple) throws Exception {
        double wins = 0;
        for (int i = 1; i <= repetitions; i++) {
            final var order = BigInteger.probablePrime(bitLength, RNG);
            final var group = AlgebraicGroup.createGroup(order);

            final var challenger = tuple.challenger.getDeclaredConstructor(AlgebraicGroup.class, int.class)
                    .newInstance(group, q);
            final var adversary = tuple.adversary.getDeclaredConstructor(AlgebraicGroup.class, int.class)
                    .newInstance(group, q);

            boolean didWin = false;
            System.out.println("Starting Test " + i);
            try {
                final I_DHI_DY05_Reduction reduction = reductionClass
                        .getDeclaredConstructor(I_Selective_DY05_Adversary.class)
                        .newInstance(adversary);

                final var solution = reduction.run(challenger);
                didWin = challenger.testSolution(solution);
            } catch (final Exception e) {
                e.printStackTrace();
            }
            if (didWin) {
                wins++;
                ConsoleHelper.printlnGreen(stdOut, "Test " + i + " finished with a success");
            } else
                ConsoleHelper.printlnRed(stdOut, "Test " + i + " finished. Your code failed");
            System.out.println();
        }
        return wins;
    }

    @Override
    protected void printFinishMessage() {
        int a = (int) Math.round(currentPoints);
        int b = (int) Math.round(maxPoints);
        if (a < b)
            ConsoleHelper.printlnRed(stdOut, "Your reduction only succeeded in " + a + " of " + b + " cases!");
        else
            ConsoleHelper.printlnGreen(stdOut, "Your reduction passed all " + b + " tests!");

        stdOut.println();
        stdOut.println(disclaimerMessage);
    }

    public static void main(final String[] args) {
        final var test = new DHI_DY05_TestRunner(DHI_DY05_Reduction.class, 10);
        test.execute();
    }
}
