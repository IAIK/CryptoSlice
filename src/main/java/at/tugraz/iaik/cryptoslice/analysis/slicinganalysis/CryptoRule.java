package at.tugraz.iaik.cryptoslice.analysis.slicinganalysis;

import at.tugraz.iaik.cryptoslice.analysis.Analysis;
import at.tugraz.iaik.cryptoslice.analysis.slicing.SliceNode;
import at.tugraz.iaik.cryptoslice.application.CodeLine;
import at.tugraz.iaik.cryptoslice.application.DetectionLogicError;
import at.tugraz.iaik.cryptoslice.application.instructions.Constant;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.stringtemplate.v4.ST;

import java.util.*;

public abstract class CryptoRule {
  protected final Logger LOGGER = LoggerFactory.getLogger(getClass());
  protected final Analysis analysis;
  protected final ST ruleReport;
  protected final List<CodeLine> searchIds = new ArrayList<>();

  private static Comparator<SliceNode> byFuzzyLevel = new Comparator<SliceNode>() {
    @Override
    public int compare(SliceNode left, SliceNode right) {
      return Integer.compare(left.getConstant().getFuzzyLevel(), right.getConstant().getFuzzyLevel());
    }
  };

  public enum FILTER {
    ALLOW_EMPTY_VALUE, ALLOW_STRING, ALLOW_ARBITRARY_TYPES, ALLOW_EXTERNAL_METHOD, ALLOW_RESOURCE_INT, ALLOW_ARRAY, ALLOW_CONST_INT
  }

  CryptoRule(Analysis analysis) {
    this.analysis = analysis;
    this.ruleReport = analysis.getReport().getTemplate("CryptoRule");
  }

  protected abstract String check() throws DetectionLogicError;

  public static String stripEnclosingQuotes(String value) {
    String filtered = value;

    if (value.startsWith("\"") && value.endsWith("\"")) {
      filtered = value.substring(1, value.length()-1);
    }

    return filtered;
  }

  public static List<SliceNode> rankNodes(Collection<SliceNode> nodes, EnumSet filterPermissions) {
    List<SliceNode> resultNodes = new ArrayList<>();

    for (SliceNode node : nodes) {
      Constant constant = node.getConstant();

      if (constant != null && constant.getVarTypeDescription() != null && constant.getValue() != null &&
          (
            (filterPermissions.contains(FILTER.ALLOW_EXTERNAL_METHOD) && constant.getConstantType() == Constant.ConstantType.EXTERNAL_METHOD) ||
            (filterPermissions.contains(FILTER.ALLOW_STRING) && constant.getVarTypeDescription().equals("java/lang/String") &&
                constant.getConstantType() != Constant.ConstantType.EXTERNAL_METHOD) ||
            (filterPermissions.contains(FILTER.ALLOW_RESOURCE_INT) &&
                constant.getVarTypeDescription().equals("int") && constant.getConstantType() == Constant.ConstantType.FIELD_CONSTANT) ||
            (filterPermissions.contains(FILTER.ALLOW_ARRAY) && constant.getConstantType() == Constant.ConstantType.ARRAY) ||
            (filterPermissions.contains(FILTER.ALLOW_CONST_INT) &&
                // 4bit, 16bit, 32bit integer
                (constant.getVarTypeDescription().equals("const/4") || constant.getVarTypeDescription().equals("const/16") ||
                 constant.getVarTypeDescription().equals("const"))) ||
            (filterPermissions.contains(FILTER.ALLOW_ARBITRARY_TYPES) &&
                (constant.getConstantType() == Constant.ConstantType.LOCAL_VARIABLE ||
                 constant.getConstantType() == Constant.ConstantType.LOCAL_ANONYMOUS_CONSTANT)
            )
          )
        )
      {
        String value = stripEnclosingQuotes(constant.getValue());

        if (!value.equalsIgnoreCase("Basic") && (filterPermissions.contains(FILTER.ALLOW_EMPTY_VALUE) || !value.isEmpty())) {
          resultNodes.add(node);
        }
      }
    }

    Collections.sort(resultNodes, byFuzzyLevel);

    return resultNodes;
  }
}
