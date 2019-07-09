package at.tugraz.iaik.cryptoslice.analysis.slicinganalysis;

import at.tugraz.iaik.cryptoslice.analysis.Analysis;
import at.tugraz.iaik.cryptoslice.analysis.SlicingGraphStep;
import at.tugraz.iaik.cryptoslice.analysis.slicing.SliceNode;
import at.tugraz.iaik.cryptoslice.analysis.slicing.SlicerBackward;
import at.tugraz.iaik.cryptoslice.analysis.slicing.SlicingCriterion;
import at.tugraz.iaik.cryptoslice.analysis.slicing.SlicingPatternBT;
import at.tugraz.iaik.cryptoslice.application.DetectionLogicError;
import at.tugraz.iaik.cryptoslice.application.instructions.Constant;
import at.tugraz.iaik.cryptoslice.utils.PathFinder;
import at.tugraz.iaik.cryptoslice.utils.config.ConfigHandler;
import at.tugraz.iaik.cryptoslice.utils.config.ConfigKeys;
import com.google.common.base.Joiner;
import org.stringtemplate.v4.ST;

import java.util.*;

public class Rule2 extends CryptoRule {
  Rule2(Analysis analysis) {
    super(analysis);
  }

  @Override
  public String check() throws DetectionLogicError {
    LOGGER.debug("\n\n## Checking Rule 2: No non-random IV for CBC encryption");
    ruleReport.addAggr("ruleHead.{number, title}", 2, "No non-random IV for CBC encryption");

    // Track back the AlgorithmParameterSpec param in Cipher.init()
    SlicingPatternBT pattern1 = new SlicingPatternBT("javax/crypto/Cipher", "init",
        "ILjava/security/Key;Ljava/security/spec/AlgorithmParameterSpec;", 2, "");
    SlicingPatternBT pattern2 = new SlicingPatternBT("javax/crypto/Cipher", "init",
        "ILjava/security/Key;Ljava/security/spec/AlgorithmParameterSpec;Ljava/security/SecureRandom;", 2, "");
    SlicingCriterion criterion = new SlicingCriterion(pattern1);
    SlicerBackward slicer = new SlicerBackward(analysis.getApp(), searchIds);
    slicer.startSearch(criterion);
    criterion.setPattern(pattern2);
    slicer.startSearch(criterion);

    if (criterion.getSliceConstants().isEmpty()) {
      LOGGER.info("Abort: No AlgorithmParameterSpec or no constants found!");
      ruleReport.add("abortMsg", "No AlgorithmParameterSpec or no constants found!");
      return ruleReport.render();
    }

    SlicingGraphStep slicingGraphStep = new SlicingGraphStep(
        ConfigHandler.getInstance().getBooleanConfigValue(ConfigKeys.ANALYSIS_SLICEGRAPH_CREATE));
    for (Integer searchId : criterion.getSliceConstants().keySet()) {
      SliceNode startNode = criterion.getSliceTrees().get(searchId).getStartNode();
      LOGGER.info("\nFound Cipher.init() in method " + startNode.getMethod().getReadableJavaName() + " in line " +
          startNode.getCodeLine().getLineNr());

      ST cipherInitReport = analysis.getReport().getTemplate("Rule2_CipherInit");
      cipherInitReport.addAggr("info.{method, codeline}", startNode.getMethod().getReadableJavaName(),
          startNode.getCodeLine().getLineNr());

      Collection<Constant> constants = criterion.getSliceConstants().get(searchId);

      boolean foundIvParamSpec = false;
      boolean foundRandom = false;
      boolean foundSecureRandom = false;
      Constant foundStringGetBytes = null;
      boolean foundSharedPreferences = false;
      boolean unidentifiedConst = false;
      Set<String> staticIvArrays = new HashSet<>();
      List<Constant> possibleArrayElements = new ArrayList<>(); // might contain duplicates

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
          if (constant.getValue().startsWith("javax/crypto/spec/IvParameterSpec-><init>(")) {
            foundIvParamSpec = true;
          } else if (constant.getValue().startsWith("java/util/Random->")) {
            foundRandom = true;
          } else if (constant.getValue().startsWith("java/security/SecureRandom->")) {
            foundSecureRandom = true;
          } else if (constant.getValue().startsWith("java/lang/String->getBytes(")) {
            foundStringGetBytes = constant;
          } else if (constant.getValue().startsWith("android/content/SharedPreferences->")) {
            foundSharedPreferences = true;
          } else {
            unidentifiedConst = true;
          }
        } else if (constant.getConstantType() == Constant.ConstantType.ARRAY) {
          staticIvArrays.add(constant.getValue());
        } else if (constant.getConstantType() == Constant.ConstantType.LOCAL_ANONYMOUS_CONSTANT ||
            constant.getConstantType() == Constant.ConstantType.LOCAL_VARIABLE) {
          possibleArrayElements.add(constant);
        } else {
          unidentifiedConst = true;
        }
      }

      if (!foundIvParamSpec) {
        LOGGER.debug("No IvParameterSpec object found!");
        cipherInitReport.add("abortMsg", "No IvParameterSpec object found!");
        ruleReport.add("searchIds", cipherInitReport);
        continue;
      } else {
        LOGGER.debug("Found an IvParameterSpec object.");
      }

      // In case we have only one constant (IvParameterSpec) the following rules will never match.
      if (foundRandom) {
        LOGGER.warn("ALERT: Detected the use of the weak congruential PRNG java/util/Random");
        cipherInitReport.addAggr("ivParameterSpec.{random}", true);
      } else if (foundSecureRandom) {
        LOGGER.debug("Detected the use of java/util/SecureRandom");
        cipherInitReport.addAggr("ivParameterSpec.{secureRandom}", true);
      } else if (foundSharedPreferences) {
        LOGGER.debug("Detected the use of android/content/SharedPreferences");
        // TODO: cipherInitReport.addAggr("ivParameterSpec.{sharedPreferences}", true);
      } else if (!staticIvArrays.isEmpty()) {
        LOGGER.warn("ALERT: Static IV detected!");

        for (String constantIV : staticIvArrays) {
          LOGGER.warn("Array: " + constantIV);
          cipherInitReport.addAggr("staticIV.{type, value}", "Array", constantIV);
        }
      } else if (!possibleArrayElements.isEmpty() && (possibleArrayElements.size() + 1 == constants.size())) {
        /*
         * Check if we have multiple LOCAL_ANONYMOUS_CONSTANT that are assembled to an array (most likely in <clinit>).
         * This is the case if there are only constants of that type and one IvParameterSpec object.
         */
        LOGGER.warn("ALERT: Static IV detected!");

        List<String> possibleArrayStringsVal = new ArrayList<>();
        for (Constant constantKey : possibleArrayElements)
          possibleArrayStringsVal.add(constantKey.getValue());

        String constantDesc = (possibleArrayElements.size() == 1) ? "constant" : "constants";
        LOGGER.warn("Array composed of single " + constantDesc + ": " +
            Joiner.on(" ").skipNulls().join(possibleArrayStringsVal));
        cipherInitReport.addAggr("staticIV.{type, value}", "AssembledArray",
            Joiner.on(" ").skipNulls().join(possibleArrayStringsVal));
      } else if (foundStringGetBytes != null/* && !unidentifiedConst && !possibleArrayElements.isEmpty()*/) {
        /*
         * Look for a triple combination: IvParameterSpec, String->getBytes() and a string.
         * The flow would be something like: IvParameterSpec("constantIv".getBytes());
         *
         * The criterion is rather relaxed: only require the presence of String.getBytes(...)
         */
        List<SliceNode> stringIVs = rankNodes(PathFinder.getLeafs(criterion.getSliceTrees().get(searchId)),
            EnumSet.of(FILTER.ALLOW_STRING, FILTER.ALLOW_EMPTY_VALUE));

        if (!stringIVs.isEmpty()) {
          LOGGER.warn("ALERT: Static IV detected!");

          // The same string might be printed multiple times if set on distinct locations,
          // e.g. if the string comes from a field, all PUT operations with IV settings were sliced.
          for (SliceNode stringIV : stringIVs) {
            Constant stringIVNode = stringIV.getConstant();
            String stringIVValue = stripEnclosingQuotes(stringIVNode.getValue());
            if (stringIVNode.getFuzzyLevel() == 0) {
              LOGGER.info("String: " + stringIVValue);
            } else {
              LOGGER.info("String (likelihood " + (100 / (stringIVNode.getFuzzyLevel() + 1)) + "%): " + stringIVValue);
            }
            cipherInitReport.addAggr("staticIV.{type, value}", "String", stringIVValue);
          }
        }
      }

      /*for (Constant constant : constants)
        System.out.println("RAW: " + constant.toString());*/
      String dotName = analysis.getApp().getApplicationName() + "_Rule2_" + searchId;
      slicingGraphStep.printSliceTrees(criterion.getSliceTrees().get(searchId), criterion.getPattern(), dotName);

      ruleReport.add("searchIds", cipherInitReport);
    }

    return ruleReport.render();
  }
}
