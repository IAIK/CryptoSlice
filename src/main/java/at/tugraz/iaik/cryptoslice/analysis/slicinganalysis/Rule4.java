package at.tugraz.iaik.cryptoslice.analysis.slicinganalysis;

import at.tugraz.iaik.cryptoslice.analysis.Analysis;
import at.tugraz.iaik.cryptoslice.analysis.slicing.SlicerBackward;
import at.tugraz.iaik.cryptoslice.analysis.slicing.SlicingCriterion;
import at.tugraz.iaik.cryptoslice.analysis.slicing.SlicingPatternBT;
import at.tugraz.iaik.cryptoslice.application.CodeLine;
import at.tugraz.iaik.cryptoslice.application.DetectionLogicError;
import at.tugraz.iaik.cryptoslice.application.instructions.Constant;
import com.google.common.base.Joiner;
import com.google.common.collect.ImmutableList;
import org.stringtemplate.v4.ST;

import java.util.*;

public class Rule4 extends CryptoRule {
  Rule4(Analysis analysis) {
    super(analysis);
  }

  @Override
  public String check() throws DetectionLogicError {
    LOGGER.debug("\n\n## Checking Rule 4: Do not use constant salts for PBE");
    ruleReport.addAggr("ruleHead.{number, title}", 4, "Do not use constant salts for PBE");

    // Track back the salt param in PBEKeySpec and PBEParameterSpec constructors.
    ImmutableList<SlicingPatternBT> patterns = ImmutableList.of(
        new SlicingPatternBT("javax/crypto/spec/PBEKeySpec", "<init>", "[C[BI", 1, ""),
        new SlicingPatternBT("javax/crypto/spec/PBEKeySpec", "<init>", "[C[BII", 1, ""),
        new SlicingPatternBT("javax/crypto/spec/PBEParameterSpec", "<init>", null, 0, ""),
        new SlicingPatternBT("org/spongycastle/crypto/generators/PKCS5S2ParametersGenerator", "init", null, 1, ""),
        new SlicingPatternBT("org/spongycastle/crypto/generators/PKCS5S1ParametersGenerator", "init", null, 1, ""),
        new SlicingPatternBT("org/spongycastle/crypto/generators/PKCS12ParametersGenerator", "init", null, 1, ""),
        new SlicingPatternBT("org/spongycastle/crypto/generators/OpenSSLPBEParametersGenerator", "init", null, 1, "")
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

      ST pbeKeySpecReport = analysis.getReport().getTemplate("Rule4_PBEKeySpecSalt");
      pbeKeySpecReport.addAggr("info.{method, codeline}", startLine.getMethod().getReadableJavaName(), startLine.getLineNr());

      Collection<Constant> constants = criterion.getSliceConstants().get(searchId);

      boolean foundRandom = false;
      boolean foundSecureRandom = false;
      Constant foundStringGetBytes = null;
      boolean unidentifiedConst = false;
      Set<String> possibleSaltArrays = new HashSet<>();
      List<Constant> possibleSaltStrings = new ArrayList<>(); // might contain duplicates

      /*
       * The following patterns looks for one or more constants that satisfy certain criteria:
       * - Final Array(s):
       *   Appear exclusively in the list, without further constants.
       *   Can be multiple though, i.e. when performing PUT on a field from two different locations.
       * - Statically assembled array:
       *   One or multiple LOCAL_ANONYMOUS_CONSTANT constants that are assembled to an array (most likely in <clinit>).
       *   The array is the PUT into a field. Given if these constants stand alone in the list.
       * - A "string".getBytes(...) situation:
       *   The String->getBytes() method is used.
       *   A LOCAL_ANONYMOUS_CONSTANT or LOCAL_VARIABLE has the dataType java/lang/String.
       *   An occasional charset parameter for getBytes() needs to be filtered out as well as duplicate values.
       */
      for (Constant constant : constants) {
        if (constant.getConstantType() == Constant.ConstantType.EXTERNAL_METHOD && constant.getValue() != null) {
          if (constant.getValue().startsWith("java/lang/String->getBytes(")) {
            foundStringGetBytes = constant;
          } else if (constant.getValue().startsWith("java/util/Random->")) {
            foundRandom = true;
          } else if (constant.getValue().startsWith("java/security/SecureRandom->")) {
            foundSecureRandom = true;
          } else {
            unidentifiedConst = true;
          }
        } else if (constant.getConstantType() == Constant.ConstantType.ARRAY) {
          possibleSaltArrays.add(constant.getValue());
        } else if (constant.getConstantType() == Constant.ConstantType.LOCAL_ANONYMOUS_CONSTANT ||
            constant.getConstantType() == Constant.ConstantType.LOCAL_VARIABLE) {
          possibleSaltStrings.add(constant);
        } else {
          unidentifiedConst = true;
        }
      }

      // Check if we have a constant array assigned
      if (foundRandom) {
        LOGGER.warn("ALERT: Detected the use of the weak congruential PRNG java/util/Random");
        pbeKeySpecReport.addAggr("pbeKeySpec.{random}", true);
      } else if (foundSecureRandom) {
        LOGGER.debug("Detected the use of java/util/SecureRandom");
        pbeKeySpecReport.addAggr("pbeKeySpec.{secureRandom}", true);
      } else if (!possibleSaltArrays.isEmpty() && (possibleSaltArrays.size() == constants.size())) {
        LOGGER.warn("ALERT: Detected the use of a constant array as salt for PBE!");

        for (String constantKey : possibleSaltArrays) {
          LOGGER.debug("Array: " + constantKey);
          pbeKeySpecReport.addAggr("constantSalt.{type, value}", "Array", constantKey);
        }
      } else if (!possibleSaltStrings.isEmpty() && (possibleSaltStrings.size() == constants.size())) {
        LOGGER.warn("ALERT: Detected the use of a constant array as salt for PBE!");

        List<String> possibleSaltStringsVal = new ArrayList<>();
        for (Constant constantKey : possibleSaltStrings)
          possibleSaltStringsVal.add(constantKey.getValue());

        String constantDesc = (possibleSaltStrings.size() == 1) ? "constant" : "constants";
        LOGGER.warn("Array composed of single " + constantDesc + ": " +
            Joiner.on(" ").skipNulls().join(possibleSaltStringsVal));
        pbeKeySpecReport.addAggr("constantSalt.{type, value}", "AssembledArray",
            Joiner.on(" ").skipNulls().join(possibleSaltStringsVal));
      } else if (foundStringGetBytes != null && !unidentifiedConst && !possibleSaltStrings.isEmpty()) {
        /*
         * Filter strings that have a higher fuzzy level than the String->getBytes() EXTERNAL_METHOD. In the example
         * getBytes("UTF-8"), getBytes() would have fuzzylevel x and UTF-8 x+1. This way, we exclude impossible strings.
         * The used Set also filters eventual duplicate strings.
         */
        Set<String> constantKeys = new HashSet<>();
        for (Constant constantKey : possibleSaltStrings) {
          if (constantKey.getFuzzyLevel() <= foundStringGetBytes.getFuzzyLevel())
            constantKeys.add(constantKey.getValue());
        }

        if (!constantKeys.isEmpty()) {
          LOGGER.warn("ALERT: Detected the use of a constant string as salt for PBE!");

          for (String constantValue : constantKeys) {
            LOGGER.warn("String: " + constantValue);
            pbeKeySpecReport.addAggr("constantSalt.{type, value}", "String",
                stripEnclosingQuotes(constantValue));
          }
        }
      }

      /*for (Constant constant : constants)
        System.out.println("RAW: " + constant.toString());*/

      ruleReport.add("searchIds", pbeKeySpecReport);
    }

    return ruleReport.render();
  }
}
