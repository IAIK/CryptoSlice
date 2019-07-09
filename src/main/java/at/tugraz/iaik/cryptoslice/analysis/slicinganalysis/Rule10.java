package at.tugraz.iaik.cryptoslice.analysis.slicinganalysis;

import at.tugraz.iaik.cryptoslice.analysis.Analysis;
import at.tugraz.iaik.cryptoslice.analysis.slicing.SlicerBackward;
import at.tugraz.iaik.cryptoslice.analysis.slicing.SlicingCriterion;
import at.tugraz.iaik.cryptoslice.analysis.slicing.SlicingPatternBT;
import at.tugraz.iaik.cryptoslice.application.CodeLine;
import at.tugraz.iaik.cryptoslice.application.DetectionLogicError;
import at.tugraz.iaik.cryptoslice.application.instructions.Constant;
import org.stringtemplate.v4.ST;

import java.util.*;

public class Rule10 extends CryptoRule {
  Rule10(Analysis analysis) {
    super(analysis);
  }

  @Override
  public String check() throws DetectionLogicError {
    LOGGER.debug("\n\n## Checking Rule 10: No constant primes for RSA");
    ruleReport.addAggr("ruleHead.{number, title}", 10, "No constant primes for RSA");

    // First parameter modulus, second privateExponent or publicExponent
    SlicingPatternBT pattern = new SlicingPatternBT("java/security/spec/RSAPrivateKeySpec", "<init>", null, 1, "");
    SlicingCriterion criterion = new SlicingCriterion(pattern);
    SlicerBackward slicer = new SlicerBackward(analysis.getApp(), searchIds);
    slicer.startSearch(criterion);

    if (criterion.getSliceConstants().isEmpty()) {
      LOGGER.info("Abort: No RSAPrivateKeySpec constructor or no constants found!");
      ruleReport.add("abortMsg", "No RSAPrivateKeySpec constructor or no constants found!");
      return ruleReport.render();
    }

    for (Integer searchId : criterion.getSliceConstants().keySet()) {
      CodeLine startLine = searchIds.get(searchId);
      LOGGER.info("\nFound RSAPrivateKeySpec constructor in method " +
          startLine.getMethod().getReadableJavaName() + " in line " + startLine.getLineNr());

      ST rsaKeySpecReport = analysis.getReport().getTemplate("Rule10_RSAKeySpec");
      rsaKeySpecReport.addAggr("info.{method, codeline}", startLine.getMethod().getReadableJavaName(), startLine.getLineNr());

      Collection<Constant> constants = criterion.getSliceConstants().get(searchId);

      boolean foundBigInteger = false;
      boolean unidentifiedConst = false;
      List<Constant> possibleKeyStrings = new ArrayList<>();

      for (Constant constant : constants) {
        if (constant.getConstantType() == Constant.ConstantType.EXTERNAL_METHOD && constant.getValue() != null) {
          if (constant.getValue().startsWith("java/math/BigInteger")) {
            foundBigInteger = true;
          } else {
            unidentifiedConst = true;
          }
        } else if (constant.getConstantType() == Constant.ConstantType.LOCAL_ANONYMOUS_CONSTANT ||
            constant.getConstantType() == Constant.ConstantType.LOCAL_VARIABLE) {
          possibleKeyStrings.add(constant);
        } else {
          unidentifiedConst = true;
        }
      }

      if (!unidentifiedConst && !possibleKeyStrings.isEmpty()) {
        LOGGER.warn("ALERT: Detected the use of a constant prime for the private RSA key!");

        for (Constant constant : possibleKeyStrings) {
          String constantValue = constant.getValue();
          LOGGER.warn("String: " + constantValue);
          rsaKeySpecReport.addAggr("constantKey.{type, value}", "String", stripEnclosingQuotes(constantValue));
        }
      }

      /*for (Constant constant : constants)
        System.out.println("RAW: " + constant.toString());*/

      ruleReport.add("searchIds", rsaKeySpecReport);
    }

    return ruleReport.render();
  }
}
