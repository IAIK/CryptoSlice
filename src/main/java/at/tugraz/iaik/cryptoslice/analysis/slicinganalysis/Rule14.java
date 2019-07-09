package at.tugraz.iaik.cryptoslice.analysis.slicinganalysis;

import at.tugraz.iaik.cryptoslice.analysis.Analysis;
import at.tugraz.iaik.cryptoslice.analysis.slicing.SliceNode;
import at.tugraz.iaik.cryptoslice.analysis.slicing.SlicerBackward;
import at.tugraz.iaik.cryptoslice.analysis.slicing.SlicingCriterion;
import at.tugraz.iaik.cryptoslice.analysis.slicing.SlicingPatternBT;
import at.tugraz.iaik.cryptoslice.application.CodeLine;
import at.tugraz.iaik.cryptoslice.application.DetectionLogicError;
import at.tugraz.iaik.cryptoslice.application.SmaliClass;
import at.tugraz.iaik.cryptoslice.application.instructions.Constant;
import at.tugraz.iaik.cryptoslice.utils.PathFinder;
import com.google.common.collect.ImmutableList;

import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;

public class Rule14  extends CryptoRule {
  Rule14(Analysis analysis) {
    super(analysis);
  }

  @Override
  public String check() throws DetectionLogicError {
    LOGGER.debug("\n\n## Checking Rule 14: Detect constant SQLCipher passwords");
    ruleReport.addAggr("ruleHead.{number, title}", 14, "Detect constant SQLCipher passwords");

    // Directly trackable invocations
    ImmutableList<SlicingPatternBT> patterns = ImmutableList.of(
        new SlicingPatternBT("net/sqlcipher/database/SQLiteDatabase", "changePassword", "*", 0, ""),
        new SlicingPatternBT("net/sqlcipher/database/SQLiteDatabase", "openDatabase", "*", 1, ""),
        new SlicingPatternBT("net/sqlcipher/database/SQLiteDatabase", "openOrCreateDatabase", "*", 1, ""),
        new SlicingPatternBT("net/sqlcipher/database/SQLiteDatabase", "create", "*", 1, ""),
        new SlicingPatternBT("net/sqlcipher/database/SQLiteDatabase", "<init>", "*", 1, ""),
        // SQLiteOpenHelper is abstract but subclasses may call these two super methods in any custom method.
        new SlicingPatternBT("net/sqlcipher/database/SQLiteOpenHelper", "getReadableDatabase", "Ljava/lang/String;", 0, ""),
        new SlicingPatternBT("net/sqlcipher/database/SQLiteOpenHelper", "getWritableDatabase", "Ljava/lang/String;", 0, "")
    );

    // Subclasses of SQLiteOpenHelper
    List<SlicingPatternBT> sqliteOpenHelperSubclasses = new ArrayList<>(patterns);
    for (SmaliClass smaliClass : analysis.getApp().getAllSmaliClasses()) {
      if (smaliClass.extendsClass("net/sqlcipher/database/SQLiteOpenHelper")) {
        sqliteOpenHelperSubclasses.add(
            new SlicingPatternBT(smaliClass.getFullClassName(false), "getReadableDatabase", "Ljava/lang/String;", 0, ""));
        sqliteOpenHelperSubclasses.add(
            new SlicingPatternBT(smaliClass.getFullClassName(false), "getWritableDatabase", "Ljava/lang/String;", 0, ""));
      }
    }

    SlicingCriterion criterion = new SlicingCriterion();
    SlicerBackward slicer = new SlicerBackward(analysis.getApp(), searchIds);
    for (SlicingPatternBT pattern : sqliteOpenHelperSubclasses) {
      criterion.setPattern(pattern);
      slicer.startSearch(criterion);
    }

    if (criterion.getSliceConstants().isEmpty()) {
      LOGGER.info("Abort: No SQLCipher loading or no password found!");
      ruleReport.add("abortMsg", "No SQLCipher loading or no password found!");
      return ruleReport.render();
    }

    for (Integer searchId : criterion.getSliceTrees().keySet()) {
      CodeLine startLine = searchIds.get(searchId);
      LOGGER.info("\nFound SQLCipher password in method " +
          startLine.getMethod().getReadableJavaName() + " in line " + startLine.getLineNr());

      List<SliceNode> passwords = rankNodes(PathFinder.getLeafs(criterion.getSliceTrees().get(searchId)),
          EnumSet.of(FILTER.ALLOW_STRING, FILTER.ALLOW_EMPTY_VALUE));

      if (!passwords.isEmpty()) {
        for (SliceNode password : passwords) {
          Constant passwordNode = password.getConstant();
          String passwordValue = stripEnclosingQuotes(passwordNode.getValue());
          if (passwordValue.isEmpty()) {
            passwordValue = "<empty> --> usage without encipherment!";
          }

          if (passwordNode.getFuzzyLevel() == 0) {
            LOGGER.info("Password: " + passwordValue);
          } else {
            LOGGER.info("Password (likelihood " + (100 / (passwordNode.getFuzzyLevel() + 1)) + "%): " + passwordValue);
          }
        }
      }
    }

    return ruleReport.render();
  }
}
