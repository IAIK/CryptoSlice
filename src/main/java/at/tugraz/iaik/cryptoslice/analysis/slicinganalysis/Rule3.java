package at.tugraz.iaik.cryptoslice.analysis.slicinganalysis;

import at.tugraz.iaik.cryptoslice.analysis.Analysis;
import at.tugraz.iaik.cryptoslice.analysis.SlicingGraphStep;
import at.tugraz.iaik.cryptoslice.analysis.slicing.*;
import at.tugraz.iaik.cryptoslice.application.CodeLine;
import at.tugraz.iaik.cryptoslice.application.DetectionLogicError;
import at.tugraz.iaik.cryptoslice.application.instructions.Constant;
import at.tugraz.iaik.cryptoslice.utils.PathFinder;
import at.tugraz.iaik.cryptoslice.utils.config.ConfigHandler;
import at.tugraz.iaik.cryptoslice.utils.config.ConfigKeys;
import com.google.common.base.Predicate;
import com.google.common.collect.*;
import org.stringtemplate.v4.ST;

import java.util.*;

public class Rule3 extends CryptoRule {
  private static final Set<String> ASYMMETRIC_BLOCK_CIPHERS = ImmutableSet.of("DHIES", "ECIES", "ElGamal", "RSA");

  private enum STATUS {
    EDIT_TEXT, SHARED_PREF
  }

  /**
   * Sorting convention:
   * 1. Sort ascending by fuzzy level
   * 2. Preference order: strings, arrays, const/4 etc.
   *
   * Ideas:
   * - Shift those constants (potential keys) to the end which appear within a .catch { ... } statement.
   * Can be found out using SliceNode.getBasicBlock().isCatch()
   * - Measure and sort by the instruction distance between the SecretKeySpec call and the const.
   */
  private static Comparator<SliceNode> byConvention = new Comparator<SliceNode>() {
    public int compare(SliceNode left, SliceNode right) {
      Constant constLeft = left.getConstant();
      Constant constRight = right.getConstant();
      String varTypeLeft = constLeft.getVarTypeDescription();
      String varTypeRight = constRight.getVarTypeDescription();

      int fuzzyCmp = Integer.compare(constLeft.getFuzzyLevel(), right.getConstant().getFuzzyLevel());
      if (fuzzyCmp != 0) {
        return fuzzyCmp;
      }

      if (!varTypeLeft.equals(varTypeRight)) {
        // 1st order: Prefer either left or right if one contains a string
        if (varTypeLeft.equals("java/lang/String")) return -1;
        if (varTypeRight.equals("java/lang/String")) return 1;
        // 2nd order: After strings, prefer arrays
        if (varTypeLeft.equals("byte[]")) return -1;
        if (varTypeRight.equals("byte[]")) return 1;
      }

      return 0;
    }
  };

  Rule3(Analysis analysis) {
    super(analysis);
  }

  @Override
  public String check() throws DetectionLogicError {
    LOGGER.debug("\n\n## Checking Rule 3: Do not use constant encryption keys");
    ruleReport.addAggr("ruleHead.{number, title}", 3, "Do not use constant encryption keys");

    // Track back the key parameter (parameterIndex 0) in all SecretKeySpec constructors.
    SlicingPatternBT pattern = new SlicingPatternBT("javax/crypto/spec/SecretKeySpec", "<init>", null, 0, "");
    SlicingCriterion criterion = new SlicingCriterion(pattern);
    SlicerBackward slicer = new SlicerBackward(analysis.getApp(), searchIds);
    slicer.startSearch(criterion);

    if (criterion.getSliceConstants().isEmpty()) {
      LOGGER.info("Abort: No SecretKeySpec constructor or no constants found!");
      ruleReport.add("abortMsg", "No SecretKeySpec constructor or no constants found!");
      return ruleReport.render();
    }

    SlicingGraphStep slicingGraphStep = new SlicingGraphStep(
        ConfigHandler.getInstance().getBooleanConfigValue(ConfigKeys.ANALYSIS_SLICEGRAPH_CREATE));
    for (Integer searchId : criterion.getSliceTrees().keySet()) {
      CodeLine startLine = searchIds.get(searchId);
      SliceTree tree = criterion.getSliceTrees().get(searchId);
      LOGGER.info("\nFound SecretKeySpec constructor in method " + startLine.getMethod().getReadableJavaName() +
          " in line " + startLine.getLineNr());

      ST secretKeySpecReport = analysis.getReport().getTemplate("Rule3_SecretKeySpec");
      secretKeySpecReport.addAggr("info.{method, codeline}", startLine.getMethod().getReadableJavaName(), startLine.getLineNr());

      // Extract all probable leafs
      List<SliceNode> leafs = rankNodes(PathFinder.getLeafs(tree),
          EnumSet.of(FILTER.ALLOW_STRING, FILTER.ALLOW_ARRAY, FILTER.ALLOW_CONST_INT));
      leafs.forEach(potentialKey -> LOGGER.trace("Potential key: {}", potentialKey.getConstant()));

      // One constant might be reached by multiple paths => MultiMap
      Multimap<SliceNode, List<SliceNode>> constantKeyPaths = MultimapBuilder.hashKeys().arrayListValues().build();
      Map<SliceNode, STATUS> miscPathFindings = new HashMap<>();
      List<List<SliceNode>> possiblePaths = PathFinder.extractAllPathsToLeafs(tree, tree.getStartNode(), Sets.newHashSet(leafs));
      for (List<SliceNode> path : possiblePaths) {
        LOGGER.trace("\nNew path");
        STATUS miscFinding = null;
        boolean unidentifiedConst = false;

        for (int i = 0; i < path.size(); i++) { // Check each SliceNode of path
          SliceNode currentNode = path.get(i);
          Constant startConst = path.get(0).getConstant();
          Constant currentConst = currentNode.getConstant();
          LOGGER.trace("{}", currentNode.getCodeLine());

          if (currentConst != null && currentConst.getConstantType() == Constant.ConstantType.EXTERNAL_METHOD && currentConst.getValue() != null) {
            // Don't allow const/4 v6, 0x0 and invoke-virtual {v6}, Ljava/lang/String;->toCharArray()[C
            // => const/4 v6, 0x0 could be set as string object (= null string) but that is practically unusable (null pointer)
            if ((currentConst.getValue().startsWith("java/lang/String->") || currentConst.getValue().startsWith("java/lang/StringBuilder->")) &&
                startConst != null && startConst.getVarTypeDescription().equals("java/lang/String")) {
              LOGGER.trace("Found a string function.");
            } else if (i != (path.size() - 1)) { // Do not flag the starting point of backward slicing (e.g. PBEKeySpec) as unidentified
              // miscFinding values are exclusive -> value might not change with subsequent loop iterations
              if (currentConst.getValue().startsWith("android/widget/EditText->")) {
                miscFinding = STATUS.EDIT_TEXT;
              } else if (currentConst.getValue().startsWith("android/content/SharedPreferences->")) {
                miscFinding = STATUS.SHARED_PREF;
              }

              unidentifiedConst = true;
              // no break here, otherwise we wouldn't disclose misc usages (e.g. shared prefs)
            }
          }
        }

        if (!unidentifiedConst) { // either only constants or a string
          String keyValue = stripEnclosingQuotes(path.get(0).getConstant().getValue());
          // Exclude 0 keys (mostly occurring as initial variable declariations or exceptions)
          if (keyValue.equals("0")  || keyValue.equals("0x0")) {
            LOGGER.debug("Found 0 or 0x0 -> ignoring");
            continue;
          }

          constantKeyPaths.put(path.get(0), path);
        } else if (miscFinding != null) {
          miscPathFindings.put(path.get(0), miscFinding);
        }
      }

      // It is checked if the used SecretKeySpec call is applied using an asymmetric cipher.
      // If so, the key is considered as public key in asymmetric cryptography which can be hardcoded legitimately.
      if (!constantKeyPaths.isEmpty()) {
        if (isAsymmetricCipher(startLine)) {
          LOGGER.debug("Detected a constant that is used as key for public-key cryptography.");
        } else {
          LOGGER.warn("ALERT: Detected the use of a constant as encryption key!");
        }
      }

      // Output hard-coded keys
      List<SliceNode> potentialKeys = new ArrayList<>(constantKeyPaths.keySet());
      potentialKeys.sort(byConvention);

      for (SliceNode potentialKey : potentialKeys) {
        Constant keyNode = potentialKey.getConstant();
        String keyValue = stripEnclosingQuotes(keyNode.getValue());

        LOGGER.info("");
        if (keyNode.getFuzzyLevel() == 0) {
          LOGGER.info("Key: " + keyValue);
        } else {
          LOGGER.info("Key (likelihood " + (100 / (keyNode.getFuzzyLevel() + 1)) + "%): " + keyValue);
        }

        if (LOGGER.isDebugEnabled()) {
          LOGGER.debug("Node: {}\n", keyNode);
          Collection<List<SliceNode>> pathSet = constantKeyPaths.get(potentialKey);
          for (List<SliceNode> path : pathSet) {
            LOGGER.debug("Possible path:");
            path.forEach(pathElement -> LOGGER.debug("{}\n{}", pathElement.getCodeLine(), pathElement.getCodeLine().getSmaliClass().getFullClassName(false)));
          }
        }
      }

      // Output misc paths
      for (Map.Entry<SliceNode, STATUS> endNode : miscPathFindings.entrySet()) {
        LOGGER.debug("Node: {}\n", endNode.getKey().getConstant());
        if (endNode.getValue() == STATUS.EDIT_TEXT) {
          LOGGER.info("Key is user-provided by input field {}", endNode.getKey().getConstant().getValue());
        } else if (endNode.getValue() == STATUS.SHARED_PREF) {
          LOGGER.info("Key is stored in the Shared Preferences by key {}", endNode.getKey().getConstant().getValue());
        }
      }

      // TODO: Assembled array not yet supported. Need app for testing!

      // TODO report logging:
      // secretKeySpecReport.addAggr("key.{isAsymmetric, type, value}", isAsymmetric, "String", stringKeyValue);
      // secretKeySpecReport.addAggr("key.{isAsymmetric, type, value}", true, "Array", constantKey);
      // secretKeySpecReport.addAggr("key.{isAsymmetric, type, value}", true, "AssembledArray", Joiner.on(" ").skipNulls().join(possibleKeyStringsVal));

      /* // Assembled array:
      } else if (!possibleKeyStrings.isEmpty() && (possibleKeyStrings.size() == constants.size())) {
        List<String> possibleKeyStringsVal = new ArrayList<>();
        for (Constant constantKey : possibleKeyStrings)
          possibleKeyStringsVal.add(constantKey.getValue());

        // Allow the use of constant (public) keys for asymmetric ciphers
        String constantDesc = (possibleKeyStrings.size() == 1) ? "constant" : "constants";
        if (isAsymmetricCipher(startLine)) {
          LOGGER.debug("Detected a constant array that is used as key for public-key cryptography.");
          LOGGER.debug("Array composed of single " + constantDesc + ": " +
              Joiner.on(" ").skipNulls().join(possibleKeyStringsVal));
          secretKeySpecReport.addAggr("key.{isAsymmetric, type, value}", true, "AssembledArray",
              Joiner.on(" ").skipNulls().join(possibleKeyStringsVal));
        } else {
          LOGGER.warn("ALERT: Detected the use of a constant array as encryption key!");
          LOGGER.warn("Array composed of single " + constantDesc + ": " +
              Joiner.on(" ").skipNulls().join(possibleKeyStringsVal));
          secretKeySpecReport.addAggr("key.{isAsymmetric, type, value}", false, "AssembledArray",
              Joiner.on(" ").skipNulls().join(possibleKeyStringsVal));
        }
      }*/

      /*System.out.println();
      for (Constant constant : criterion.getSliceConstants().get(searchId))
        System.out.println("RAW: " + constant.toString());*/

      String dotName = analysis.getApp().getApplicationName() + "_Rule3_" + searchId;
      slicingGraphStep.printSliceTrees(criterion.getSliceTrees().get(searchId), criterion.getPattern(), dotName);

      ruleReport.add("searchIds", secretKeySpecReport);
    }

    return ruleReport.render();
  }

  private boolean isAsymmetricCipher(CodeLine oldStartLine) throws DetectionLogicError {
    List<CodeLine> searchIdsNew = new ArrayList<>();
    SlicerBackward slicer = new SlicerBackward(analysis.getApp(), searchIdsNew);

    // Track back the algorithm parameter
    SlicingPatternBT pattern1 = new SlicingPatternBT("javax/crypto/spec/SecretKeySpec", "<init>",
        "[BLjava/lang/String;", 1, "");
    SlicingPatternBT pattern2 = new SlicingPatternBT("javax/crypto/spec/SecretKeySpec", "<init>",
        "[BIILjava/lang/String;", 3, "");
    SlicingCriterion criterion = new SlicingCriterion(pattern1);
    slicer.startSearch(criterion);
    criterion.setPattern(pattern2);
    slicer.startSearch(criterion);

    if (criterion.getSliceConstants().isEmpty())
      return false;

    /*
     * Try to find the new searchId, associated with the given codeline because it is not possible to use the old one.
     * Different slicing patterns can lead to different result ordering and thus different searchId values.
     */
    int searchId = searchIdsNew.indexOf(oldStartLine);
    if (searchId == -1)
      return false;

    // Filter all constants that describe an asymmetric cipher pattern.
    Constant cipherConstant = Iterables.find(criterion.getSliceConstants().get(searchId), new Predicate<Constant>() {
      @Override
      public boolean apply(Constant constant) {
        // The cipher has to be a String with non-null value
        return (constant.getVarTypeDescription() != null && constant.getValue() != null &&
            constant.getVarTypeDescription().equals("java/lang/String") && containsCipher(constant.getValue()));
      }
    }, null);

    // Having no constant at this point means that there is no asymmetric cipher.
    return (cipherConstant != null);
  }

  private boolean containsCipher(String value) {
    // Pattern to match DHIESwithAES, DHIES/DHAES/PKCS7Padding), RSA//RAW, RSA/ISO9796-1, RSA/ECB/PKCS1Padding
    for (String cipher : ASYMMETRIC_BLOCK_CIPHERS) {
      if (value.matches("(?i)^\"" + cipher + ".*\"$")) { // All strings come quoted!
        LOGGER.trace("Matching pattern " + cipher);
        return true;
      }
    }

    return false;
  }
}
