package at.tugraz.iaik.cryptoslice.analysis.slicinganalysis;

import at.tugraz.iaik.cryptoslice.analysis.Analysis;
import at.tugraz.iaik.cryptoslice.analysis.slicing.ResourceUtils;
import at.tugraz.iaik.cryptoslice.analysis.slicing.SlicerForward;
import at.tugraz.iaik.cryptoslice.analysis.slicing.SlicingCriterion;
import at.tugraz.iaik.cryptoslice.analysis.slicing.SlicingPatternFT;
import at.tugraz.iaik.cryptoslice.application.Application;
import at.tugraz.iaik.cryptoslice.application.CodeLine;
import at.tugraz.iaik.cryptoslice.application.DetectionLogicError;
import at.tugraz.iaik.cryptoslice.application.instructions.Constant;
import org.stringtemplate.v4.ST;

import java.util.Collection;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public class Rule8 extends CryptoRule {
  Rule8(Analysis analysis) {
    super(analysis);
  }

  @Override
  public String check() throws DetectionLogicError {
    LOGGER.debug("\n\n## Checking Rule 8: No password leaks");
    ruleReport.addAggr("ruleHead.{number, title}", 8, "No password leaks");

    Application app = analysis.getApp();
    Set<String> resourceIds = new HashSet<>();
    resourceIds.addAll(ResourceUtils.findResourceIdsForInputType("//EditText[contains(@inputType, 'textPassword')]", app));
    resourceIds.addAll(ResourceUtils.findResourceIdsForInputType("//EditText[contains(@inputType, 'textWebPassword')]", app));
    resourceIds.addAll(ResourceUtils.findResourceIdsForInputType("//EditText[contains(@inputType, 'textVisiblePassword')]", app));
    resourceIds.addAll(ResourceUtils.findResourceIdsForInputType("//EditText[contains(@inputType, 'numberPassword')]", app));
    resourceIds.addAll(ResourceUtils.findResourceIdsForInputType("//EditText[@password='true']", app));
    Map<String, String> constantIds = ResourceUtils.findConstForResourceIds(resourceIds, app);

    SlicerForward slicer = new SlicerForward(app, searchIds);
    SlicingCriterion criterion = new SlicingCriterion();
    for (Map.Entry<String, String> constantId : constantIds.entrySet()) {
      SlicingPatternFT pattern = new SlicingPatternFT(constantId.getKey(), "RESOURCE_ID", "");
      pattern.setConstantId(constantId.getValue());
      pattern.setEnabled(true);
      criterion.setPattern(pattern);
      slicer.startSearch(criterion);
    }

    if (criterion.getSliceConstants().isEmpty()) {
      LOGGER.info("Abort: No password field or no constants found!");
      ruleReport.add("abortMsg", "No password field or no constants found!");
      return ruleReport.render();
    }

    for (Integer searchId : criterion.getSliceConstants().keySet()) {
      CodeLine startLine = searchIds.get(searchId);
      // Search the pattern to which the codeline belongs to
      String pwField = "";
      String pwValue = "";
      for (Map.Entry<String, String> constantId : constantIds.entrySet()) {
        if (startLine.contains(constantId.getValue().getBytes())) {
          pwField = constantId.getKey();
          pwValue = constantId.getValue();
          break;
        }
      }

      // Fields can also exist without method -> use class (instead of method)
      LOGGER.info("\nFound password field " + pwField + " (" + pwValue + ") in " +
          startLine.getSmaliClass().getFullClassName(true) + " in line " + startLine.getLineNr());

      ST passwordFieldReport = analysis.getReport().getTemplate("Rule8_PasswordField");
      passwordFieldReport.addAggr("info.{pwField, pwValue, class, codeline}", pwField, pwValue,
          startLine.getSmaliClass().getFullClassName(true), startLine.getLineNr());

      Collection<Constant> constants = criterion.getSliceConstants().get(searchId);

      /*Ordering<Constant> byFuzzyLevel = new Ordering<Constant>() {
        @Override
        public int compare(Constant s1, Constant s2) {
          return Ints.compare(s1.getFuzzyLevel(), s2.getFuzzyLevel());
        }
      };

      List<Constant> logCalls = new ArrayList<>();*/
      boolean foundLog = false;
      boolean foundOutputStream = false;
      boolean foundCrypto = false;
      for (Constant constant : constants) {
        //System.out.println("RAW: " + constant.toString());
        if (constant.getValue() != null) {
          String value = constant.getValue();
          if (value.startsWith("android/util/Log")) {
            //logCalls.add(constant);
            foundLog = true;
          } else if (value.matches("(?i)^java/io/.+OutputStream.+$") || value.matches("(?i)^java/io/PrintWriter.+$") ||
              value.matches("(?i)^java/io/FileWriter.+$")) {
            foundOutputStream = true;
          } else if (value.startsWith("java/security") || value.startsWith("javax/crypto")) {
            foundCrypto = true;
          }
        }
      }

      if (foundLog)
        LOGGER.warn("ALERT: The password is probably leaked through android/util/Log!");

      if (foundOutputStream)
        LOGGER.warn("ALERT: The password is probably written to a file!");

      if (foundCrypto)
        LOGGER.debug("The password is linked to cryptographic functions.");
      else
        LOGGER.debug("The password is NOT linked to cryptographic functions.");

      passwordFieldReport.addAggr("status.{foundLog, foundOutputStream, foundCrypto}", foundLog, foundOutputStream, foundCrypto);

      //Collections.sort(logCalls, byFuzzyLevel);
      //System.out.println(logCalls);

      ruleReport.add("searchIds", passwordFieldReport);
    }

    return ruleReport.render();
  }
}
