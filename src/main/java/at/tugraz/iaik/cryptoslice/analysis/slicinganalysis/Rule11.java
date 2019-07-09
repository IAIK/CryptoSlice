package at.tugraz.iaik.cryptoslice.analysis.slicinganalysis;

import at.tugraz.iaik.cryptoslice.analysis.Analysis;
import at.tugraz.iaik.cryptoslice.analysis.slicing.*;
import at.tugraz.iaik.cryptoslice.application.CodeLine;
import at.tugraz.iaik.cryptoslice.application.DetectionLogicError;
import at.tugraz.iaik.cryptoslice.application.instructions.Constant;
import at.tugraz.iaik.cryptoslice.utils.PathFinder;
import com.google.common.collect.Iterables;
import org.stringtemplate.v4.ST;

import java.util.*;

public class Rule11 extends CryptoRule {
  Rule11(Analysis analysis) {
    super(analysis);
  }

  @Override
  public String check() throws DetectionLogicError {
    LOGGER.debug("\n\n## Checking Rule 11: Detect keystore passwords");
    ruleReport.addAggr("ruleHead.{number, title}", 11, "Detect keystore passwords");

    SlicingPatternBT pattern = new SlicingPatternBT("java/security/KeyStore", "load", "Ljava/io/InputStream;[C", 1, "");
    SlicingCriterion criterion = new SlicingCriterion(pattern);
    SlicerBackward slicer = new SlicerBackward(analysis.getApp(), searchIds);
    slicer.startSearch(criterion);

    if (criterion.getSliceConstants().isEmpty()) {
      LOGGER.info("Abort: No KeyStore loading or no password found!");
      ruleReport.add("abortMsg", "No KeyStore loading or no password found!");
      return ruleReport.render();
    }

    for (Integer searchId : criterion.getSliceConstants().keySet()) {
      CodeLine startLine = searchIds.get(searchId);
      LOGGER.info("\nFound KeyStore loading in method " +
          startLine.getMethod().getReadableJavaName() + " in line " + startLine.getLineNr() + " in " + startLine.getSmaliClass().getFile().getAbsolutePath());

      ST keyStoreReport = analysis.getReport().getTemplate("Rule11_KeyStore");
      keyStoreReport.addAggr("info.{method, codeline}", startLine.getMethod().getReadableJavaName(), startLine.getLineNr());

      // Track the first parameter: KeyStore->load(filename, X);
      List<CodeLine> searchIds2 = new ArrayList<>();
      SlicerBackward slicer2 = new SlicerBackward(analysis.getApp(), searchIds2);
      SlicingCriterion criterion2 = new SlicingCriterion(new SlicingPatternBT(startLine, 0));
      slicer2.startSearch(criterion2);

      Set<SliceNode> leafs = PathFinder.getLeafs(Iterables.get(criterion2.getSliceTrees().values(), 0));
      List<SliceNode> rankedLeafs = rankNodes(leafs, EnumSet.of(FILTER.ALLOW_STRING, FILTER.ALLOW_RESOURCE_INT, FILTER.ALLOW_ARBITRARY_TYPES));

      if (rankedLeafs.isEmpty() || rankedLeafs.size() == 1 && rankedLeafs.iterator().next().getConstant().getValue().equals("0")) {
        LOGGER.info("KeyStore filename is null. Dynamically created?!");
      } else {//if (rankedLeafs.size() == 1) {
        // Resolve raw resource ID
        boolean isRawResource = false;
        for (Constant constant : criterion2.getSliceConstants().values()) {
          if (constant.getValue().contains("android/content/res/Resources->openRawResource")) {
            isRawResource = true;
            break;
          }
        }

        if (isRawResource) {
          Constant resourceIdConstant = rankedLeafs.iterator().next().getConstant();
          String resVal = ResourceUtils.findResourceNameForResourceId(analysis.getApp().getBytecodeDecompiledDirectory(),
              resourceIdConstant.getUnparsedValue());

          if (resVal != null) {
            LOGGER.info("Filename: " + resVal);
          } else {
            LOGGER.info("Unable to resolve the filename resource ID " + resourceIdConstant.getUnparsedValue());
          }
        } else {
          Constant possibleFilename = null;
          for (SliceNode node : rankedLeafs) {
            Constant constant = node.getConstant();
            if (constant.getVarTypeDescription().equals("java/lang/String") && constant.getValue().contains(".")) { // filename.ext
              possibleFilename = constant;
              break;
            }
          }

          if (possibleFilename != null) {
            LOGGER.info("Filename: " + possibleFilename.getValue().replace("\"", ""));
          } else {
            LOGGER.info("Filename could not be determined!");
          }
        }
      }

      /*
       * There can be only one password to open a KeyStore.
       *
       * Password types:
       * - String: might be empty
       * - Nullpointer: 0x0, to create an empty keystore or if it cannot be initialized from a stream
       *
       * Strategy: What if the slice is inaccurate and finds multiple different passwords? Which is the correct one?
       * -> The password must be either LOCAL_ANONYMOUS_CONSTANT or LOCAL_VARIABLE
       * -> Prefer constants with lower fuzzy level (more likely)
       * -> Only Strings actually make sense -> else: not initialized or unavailable KeyStore
       *
       */
      leafs = PathFinder.getLeafs(criterion.getSliceTrees().get(searchId));
      rankedLeafs = rankNodes(leafs, EnumSet.of(FILTER.ALLOW_STRING, FILTER.ALLOW_EMPTY_VALUE));

      if (rankedLeafs.isEmpty()) {
        LOGGER.info("KeyStore password is null. Dynamically created?!");
      } else {
        Set<String> printedPasswords = new HashSet<>();
        for (SliceNode password : rankedLeafs) {
          Constant passwordNode = password.getConstant();
          String passwordValue = stripEnclosingQuotes(passwordNode.getValue());

          if (printedPasswords.contains(passwordValue)) {
            continue;
          } else {
            printedPasswords.add(passwordValue);
          }

          if (passwordNode.getFuzzyLevel() == 0) {
            LOGGER.info("Password: " + passwordValue);
          } else {
            LOGGER.info("Password (likelihood " + (100 / (passwordNode.getFuzzyLevel() + 1)) + "%): " + passwordValue);
          }

          keyStoreReport.add("constantPassword", password); // FIXME: This likely adds only one password to the report!
        }
      }

      ruleReport.add("searchIds", keyStoreReport);
    }

    return ruleReport.render();
  }
}
