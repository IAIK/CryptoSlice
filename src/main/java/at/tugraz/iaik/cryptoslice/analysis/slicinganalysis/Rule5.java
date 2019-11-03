package at.tugraz.iaik.cryptoslice.analysis.slicinganalysis;

import at.tugraz.iaik.cryptoslice.analysis.Analysis;
import at.tugraz.iaik.cryptoslice.analysis.slicing.SlicerBackward;
import at.tugraz.iaik.cryptoslice.analysis.slicing.SlicingCriterion;
import at.tugraz.iaik.cryptoslice.analysis.slicing.SlicingPatternBT;
import at.tugraz.iaik.cryptoslice.application.CodeLine;
import at.tugraz.iaik.cryptoslice.application.DetectionLogicError;
import at.tugraz.iaik.cryptoslice.application.instructions.Constant;
import com.google.common.collect.ImmutableList;
import org.stringtemplate.v4.ST;

import java.util.Collection;

public class Rule5 extends CryptoRule {
  private static final int MIN_ITERATIONS = 1000;

  Rule5(Analysis analysis) {
    super(analysis);
  }

  @Override
  public String check() throws DetectionLogicError {
    LOGGER.debug("\n\n## Checking Rule 5: Do not use fewer than " + MIN_ITERATIONS + " iterations for PBE");
    ruleReport.addAggr("ruleHead.{number, title}", 5, "Do not use fewer than " + MIN_ITERATIONS + " iterations for PBE");

    // Track back the iterationCount param in PBEKeySpec and PBEParameterSpec constructors.
    ImmutableList<SlicingPatternBT> patterns = ImmutableList.of(
        new SlicingPatternBT("javax/crypto/spec/PBEKeySpec", "<init>", "[C[BI", 2, ""),
        new SlicingPatternBT("javax/crypto/spec/PBEKeySpec", "<init>", "[C[BII", 2, ""),
        new SlicingPatternBT("javax/crypto/spec/PBEParameterSpec", "<init>", null, 1, ""),
        new SlicingPatternBT("org/spongycastle/crypto/generators/PKCS5S2ParametersGenerator", "init", null, 2, ""),
        new SlicingPatternBT("org/spongycastle/crypto/generators/PKCS5S1ParametersGenerator", "init", null, 2, ""),
        new SlicingPatternBT("org/spongycastle/crypto/generators/PKCS12ParametersGenerator", "init", null, 2, "")
    );

    SlicingCriterion criterion = new SlicingCriterion();
    SlicerBackward slicer = new SlicerBackward(analysis.getApp(), searchIds);
    for (SlicingPatternBT pattern : patterns) {
      criterion.setPattern(pattern);
      slicer.startSearch(criterion);
    }

    if (criterion.getSliceConstants().isEmpty()) {
      LOGGER.info("Abort: No PBEKeySpec/PBEParameterSpec or no constants found!");
      ruleReport.add("abortMsg", "No PBEKeySpec/PBEParameterSpec or no constants found!");
      return ruleReport.render();
    }

    for (Integer searchId : criterion.getSliceConstants().keySet()) {
      CodeLine startLine = searchIds.get(searchId);
      LOGGER.info("\nFound PBEKeySpec/PBEParameterSpec constructor in method " +
          startLine.getMethod().getReadableJavaName() + " in line " + startLine.getLineNr());

      ST pbeKeySpecReport = analysis.getReport().getTemplate("Rule5_PBEKeySpec");
      pbeKeySpecReport.addAggr("info.{method, codeline}", startLine.getMethod().getReadableJavaName(), startLine.getLineNr());

      Collection<Constant> constants = criterion.getSliceConstants().get(searchId);

      /*
       * The pattern to look for is a constant with the following attributes:
       * - constType = LOCAL_ANONYMOUS_CONSTANT and dataType starts with "const" (excludes java/lang/String constants),
       *   or
       *   constType = LOCAL_VARIABLE and dataType equals "int",
       * - value > 0 (as according to the PBE specification),
       *
       * - If we have only 1 constant -> found the iterationCount
       * - In the rare case that we have multiple:
       *   prefer the constant with the lower fuzzy value -> might be more accurate
       */
      Constant iterationCount = null;
      for (Constant constant : constants) {
        if ( ( (constant.getConstantType() == Constant.ConstantType.LOCAL_ANONYMOUS_CONSTANT &&
            constant.getVarTypeDescription().startsWith("const")) ||
            ((constant.getConstantType() == Constant.ConstantType.LOCAL_VARIABLE || constant.getConstantType() == Constant.ConstantType.FIELD_CONSTANT) &&
            constant.getVarTypeDescription().equals("int")) ) &&
            (constant.getValue() != null && !constant.getValue().equals("0")) &&
            (iterationCount == null || (constant.getFuzzyLevel() <= iterationCount.getFuzzyLevel())) ) {
          iterationCount = constant;
        }
      }

      if (iterationCount != null) {
        int count = Integer.parseInt(iterationCount.getValue());
        String iterationDesc = (count == 1) ? "iteration" : "iterations";
        if (count < MIN_ITERATIONS)
          LOGGER.warn("ALERT: PBE is used with only " + count + " " + iterationDesc + " (min: " + MIN_ITERATIONS + ")");
        else
          LOGGER.debug("PBE is performed with " + count + " iterations.");

        pbeKeySpecReport.addAggr("iterations.{min, pbe}", MIN_ITERATIONS, count);
      }

      /*for (Constant constant : constants)
        System.out.println("RAW: " + constant.toString());*/

      ruleReport.add("searchIds", pbeKeySpecReport);
    }

    return ruleReport.render();
  }
}
