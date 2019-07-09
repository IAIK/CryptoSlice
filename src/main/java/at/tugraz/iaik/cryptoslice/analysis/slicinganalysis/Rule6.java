package at.tugraz.iaik.cryptoslice.analysis.slicinganalysis;

import at.tugraz.iaik.cryptoslice.analysis.Analysis;
import at.tugraz.iaik.cryptoslice.analysis.slicing.SlicerBackward;
import at.tugraz.iaik.cryptoslice.analysis.slicing.SlicingCriterion;
import at.tugraz.iaik.cryptoslice.analysis.slicing.SlicingPatternBT;
import at.tugraz.iaik.cryptoslice.application.CodeLine;
import at.tugraz.iaik.cryptoslice.application.DetectionLogicError;
import at.tugraz.iaik.cryptoslice.application.instructions.Constant;
import com.google.common.base.Joiner;
import org.stringtemplate.v4.ST;

import java.util.*;

public class Rule6 extends CryptoRule {
  Rule6(Analysis analysis) {
    super(analysis);
  }

  @Override
  public String check() throws DetectionLogicError {
    LOGGER.debug("\n\n## Checking Rule 6: Do not use static seeds to seed SecureRandom()");
    ruleReport.addAggr("ruleHead.{number, title}", 6, "Do not use static seeds to seed SecureRandom()");

    /*
     * Track back the seed param from the SecureRandom constructor and setSeed method.
     * The used algorithm is not relevant because on commercial Android devices we have only SHA1PRNG.
     */
    SlicingPatternBT pattern1 = new SlicingPatternBT("java/security/SecureRandom", "<init>", "[B", 0, "");
    SlicingPatternBT pattern2 = new SlicingPatternBT("java/security/SecureRandom", "setSeed", null, 0, ""); // [B and J
    SlicingCriterion criterion = new SlicingCriterion(pattern1);
    SlicerBackward slicer = new SlicerBackward(analysis.getApp(), searchIds);
    slicer.startSearch(criterion);
    criterion.setPattern(pattern2);
    slicer.startSearch(criterion);

    if (criterion.getSliceConstants().isEmpty()) {
      LOGGER.info("Abort: No SecureRandom or no constants found!");
      ruleReport.add("abortMsg", "No SecureRandom or no constants found!");
      return ruleReport.render();
    }

    for (Integer searchId : criterion.getSliceConstants().keySet()) {
      CodeLine startLine = searchIds.get(searchId);
      LOGGER.info("\nFound SecureRandom in method " + startLine.getMethod().getReadableJavaName() + " in line " +
          startLine.getLineNr());

      ST secureRandomReport = analysis.getReport().getTemplate("Rule6_SecureRandom");
      secureRandomReport.addAggr("info.{method, codeline}", startLine.getMethod().getReadableJavaName(), startLine.getLineNr());

      Collection<Constant> constants = criterion.getSliceConstants().get(searchId);

      Constant foundStringGetBytes = null;
      boolean foundNextBytes = false;
      boolean unidentifiedConst = false;
      Set<String> possibleSeedArrays = new HashSet<>();
      List<Constant> possibleSeedStrings = new ArrayList<>();

      /*
       * The following patterns looks for one or more constants that satisfy certain criteria:
       * - Final Array(s):
       *   Appear exclusively in the list, without further constants.
       *   Can be multiple though, i.e. when performing PUT on a field from two different locations.
       * - Statically assembled array:
       *   One or multiple LOCAL_ANONYMOUS_CONSTANT constants that are assembled to an array (most likely in <clinit>).
       *   The array is the PUT into a field. Given if these constants stand alone in the list.
       * - A long integer, used for setSeed(J).
       * - A "string".getBytes(...) situation:
       *   The String->getBytes() method is used.
       *   A LOCAL_ANONYMOUS_CONSTANT or LOCAL_VARIABLE has the dataType java/lang/String.
       *   An occasional charset parameter for getBytes() needs to be filtered out as well as duplicate values.
       *
       * We also detect if the slice contains a call to java/security/SecureRandom->nextBytes([B)
       * This implies that the PRNG was seeded after a generating the pseudorandom sequence that was initially randomly
       * seeded by the PRNG. The seed now is added to the the random sequence and thus, the following sequence would be
       * predictable!
       */
      for (Constant constant : constants) {
        if (constant.getConstantType() == Constant.ConstantType.EXTERNAL_METHOD && constant.getValue() != null) {
          if (constant.getValue().startsWith("java/lang/String->getBytes(")) {
            foundStringGetBytes = constant;
          } else if (constant.getValue().startsWith("java/security/SecureRandom->nextBytes(")) {
            foundNextBytes = true;
          } else {
            unidentifiedConst = true;
          }
        } else if (constant.getConstantType() == Constant.ConstantType.ARRAY) {
          possibleSeedArrays.add(constant.getValue());
        } else if (constant.getConstantType() == Constant.ConstantType.LOCAL_ANONYMOUS_CONSTANT ||
            constant.getConstantType() == Constant.ConstantType.LOCAL_VARIABLE) {
          possibleSeedStrings.add(constant);
        } else {
          unidentifiedConst = true;
        }
      }

      // Check if we have a constant array assigned
      if (!possibleSeedArrays.isEmpty() && (possibleSeedArrays.size() == constants.size())) {
        LOGGER.warn("ALERT: Detected the use of a static seed for SecureRandom!");

        for (String constantKey : possibleSeedArrays) {
          LOGGER.warn("Array: " + constantKey);
          secureRandomReport.addAggr("staticSeed.{type, value}", "Array", constantKey);
        }
      } else if (!possibleSeedStrings.isEmpty() && (possibleSeedStrings.size() == constants.size())) {
        List<String> possibleSeedStringsVal = new ArrayList<>();
        for (Constant constantKey : possibleSeedStrings)
          possibleSeedStringsVal.add(constantKey.getValue());

        LOGGER.warn("ALERT: Detected the use of a static seed for SecureRandom!");
        // Separate output for setSeed(J) and setSeed([B) / Constructor
        if (constants.size() == 1) { // just a long-long integer
          LOGGER.warn("64-bit Integer: " + possibleSeedStringsVal.get(0));
          secureRandomReport.addAggr("staticSeed.{type, value}", "Integer", possibleSeedStringsVal.get(0));
        } else {
          String constantDesc = (possibleSeedStrings.size() == 1) ? "constant" : "constants";
          LOGGER.warn("Array composed of single " + constantDesc + ": " +
              Joiner.on(" ").skipNulls().join(possibleSeedStringsVal));
          secureRandomReport.addAggr("staticSeed.{type, value}", "AssembledArray",
              Joiner.on(" ").skipNulls().join(possibleSeedStringsVal));
        }
      } else if (foundStringGetBytes != null && !unidentifiedConst && !possibleSeedStrings.isEmpty()) {
        /*
         * Filter strings that have a higher fuzzy level than the String->getBytes() EXTERNAL_METHOD. In the example
         * getBytes("UTF-8"), getBytes() would have fuzzylevel x and UTF-8 x+1. This way, we exclude impossible strings.
         */
        Set<String> constantKeys = new HashSet<>();
        for (Constant constantKey : possibleSeedStrings) {
          if (constantKey.getFuzzyLevel() <= foundStringGetBytes.getFuzzyLevel())
            constantKeys.add(constantKey.getValue());
        }

        if (!constantKeys.isEmpty()) {
          LOGGER.warn("ALERT: Detected the use of a static seed for SecureRandom!");

          if (foundNextBytes)
            LOGGER.warn("Reseeded after a call to nextBytes()");

          for (String constantValue : constantKeys) {
            LOGGER.warn("String: " + constantValue);
            secureRandomReport.addAggr("staticSeed.{type, value}", "String",
                stripEnclosingQuotes(constantValue));
          }
        }
      }

      /*for (Constant constant : constants)
        System.out.println("RAW: " + constant.toString());*/

      ruleReport.add("searchIds", secureRandomReport);
    }

    return ruleReport.render();
  }
}
