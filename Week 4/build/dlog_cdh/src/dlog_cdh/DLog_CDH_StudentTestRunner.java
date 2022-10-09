package dlog_cdh;

import java.math.BigInteger;
import java.security.SecureRandom;

import cdh.CDH_Adversary;
import dlog.DLog_Challenger;
import genericGroups.AlgebraicGroup;
import genericGroups.GroupElement;
import genericGroups.IGroupElement;
import grading.ConsoleHelper;
import grading.StudentTestRunner;

public class DLog_CDH_StudentTestRunner extends StudentTestRunner {

    protected int repetitions;
    protected Class<? extends I_DLog_CDH_Reduction<IGroupElement, BigInteger>> reductionClass;
    private final SecureRandom RNG = new SecureRandom();

    public DLog_CDH_StudentTestRunner(
            Class<? extends I_DLog_CDH_Reduction<IGroupElement, BigInteger>> reductionClass,
            int repetitions) {
        setup(reductionClass, repetitions);
    }

    private void setup(
            final Class<? extends I_DLog_CDH_Reduction<IGroupElement, BigInteger>> reductionClass,
            int repetitions) {
        this.reductionClass = reductionClass;
        this.repetitions = repetitions;
    }

    private boolean runOneGame() throws Exception {
        var order = PrimesHelper.getRandomPrime(RNG);

        var group = AlgebraicGroup.createGroup(order);
        var generator = new GroupElement(group, BigInteger.ONE);

        var challenger = new DLog_Challenger(generator);
        var adversary = new CDH_Adversary(group);
        var reduction = reductionClass.getDeclaredConstructor().newInstance();

        reduction.setAdversary(adversary);
        var solution = reduction.run(challenger);
        return challenger.checkSolution(solution);
    }

    @Override
    public void run() throws Exception {
        this.maxPoints = 0;
        for (int i = 1; i <= repetitions; i++) {
            System.out.println("Starting Test " + i);

            maxPoints++;
            try {
                if (runOneGame()) {
                    currentPoints++;
                    ConsoleHelper.printlnGreen(stdOut, "Test " + i + " finished with a success");
                } else
                    ConsoleHelper.printlnRed(stdOut, "Test " + i + " finished. Your code failed");
                stdOut.println();
            } catch (Exception e) {
                ConsoleHelper.printlnRed(stdOut,
                        "A run of your code has thrown an exception. Therefore, the TestRunner has stopped all Tests."
                                + "Below, you will find the exception thrown by your code:");

                this.maxPoints = repetitions;

                System.out.println();
                System.out.println();

                e.printStackTrace();
                return;
            }
        }
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
        final var testrunner = new DLog_CDH_StudentTestRunner(DLog_CDH_Reduction.class, 10);
        testrunner.execute();
    }
}
