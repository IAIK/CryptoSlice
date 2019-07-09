package at.tugraz.iaik.cryptoslice.analysis;

import at.tugraz.iaik.cryptoslice.analysis.slicing.SliceNode;
import at.tugraz.iaik.cryptoslice.analysis.slicing.SliceTree;
import at.tugraz.iaik.cryptoslice.analysis.slicing.SlicingPattern;
import at.tugraz.iaik.cryptoslice.analysis.slicing.SlicingPatternBT;
import at.tugraz.iaik.cryptoslice.application.instructions.Constant;
import at.tugraz.iaik.cryptoslice.application.methods.Method;
import at.tugraz.iaik.cryptoslice.utils.config.ConfigHandler;
import at.tugraz.iaik.cryptoslice.utils.config.ConfigKeys;
import com.google.common.collect.Lists;
import com.google.common.collect.Multimap;
import com.google.common.collect.Table;
import org.apache.commons.io.FileUtils;

import java.io.File;
import java.io.IOException;
import java.util.Collection;
import java.util.Set;

// Generate graphs from the slicing results
public class SlicingGraphStep extends Step {
  public SlicingGraphStep(boolean enabled) {
    this.name = "Slice Graph";
    this.enabled = enabled;
  }

  @Override
  public boolean doProcessing(Analysis analysis) throws AnalysisException {
    // Output all trees separately
    for (Table.Cell<SlicingPattern, Integer, SliceTree> entry : analysis.getSliceTrees().cellSet()) {
      SlicingPattern slicingPattern = entry.getRowKey();
      Integer searchId = entry.getColumnKey();
      boolean isBackwardSlice = (slicingPattern.getSlicingType() == SlicingPattern.SLICING_TYPE.BACKWARD);

      String dotName = analysis.getApp().getApplicationName() + "_" + slicingPattern.hashCode() +
          (isBackwardSlice ? "-(" + ((SlicingPatternBT) slicingPattern).getParameterOfInterest() + ")" : "") +
          "_" + searchId;

      printSliceTrees(entry.getValue(), entry.getRowKey(), dotName);
    }

    return true;
  }

  public void printSliceTrees(SliceTree sliceTree, SlicingPattern slicingPattern, String dotName) {
    if (!enabled) return;

    Multimap<Method, SliceNode> sliceNodes = sliceTree.getSliceNodes();

    boolean isBackwardSlice = (slicingPattern.getSlicingType() == SlicingPattern.SLICING_TYPE.BACKWARD);

    String dot = "";
    boolean isStartMethod = true;
    for (Method method : sliceNodes.keySet()) {
      if (!isStartMethod) { // LinkedHashKeys -> first key is start method
        dot += "\tsubgraph \"cluster_" + (method.hashCode()) + "\" {\n" + "\tcolor=seagreen;\n"/* + "\tnode [style=filled];\n"*/;
      } else {
        dot += "\tsubgraph \"cluster_" + (method.hashCode()) + "\" {\n" + "\tstyle=filled;\n" + "\tcolor=skyblue;\n" + "\tnode [style=filled,color=white];\n";
        isStartMethod = false;
      }

      dot += "\tlabel=\"" + method.getReadableJavaName() + "\";\n"; // add the node itself to the subgraph

      String links = "";
      Collection<SliceNode> nodes = sliceNodes.get(method);
      nodes = Lists.reverse(Lists.newArrayList(nodes)); // descending node order
      for (SliceNode node : nodes) {
        dot += "\"" + escapeString(node.getIdentifier()) + "\"";
        // Show constant information (but not for external methods)
        if (node.getConstant() != null) {
          /*dot += " [label=\"" + escapeString(node.getIdentifier()) + "\n\n";
          // Omit the output of LOCAL_ANONYMOUS_CONSTANT -> no valuable information
          if (node.getConstant().getConstantType() != Constant.ConstantType.LOCAL_ANONYMOUS_CONSTANT)
            dot += "const type: " + node.getConstant().getConstantType().toString() + "\n";
          dot += "variable type: " + node.getConstant().getVarTypeDescription() + "\n";
          if (node.getConstant().getIdentifier() != null)
            dot += "name: " + node.getConstant().getIdentifier() + "\n";
          // Omit the value output for external methods -> it is already written in the codeline
          if (node.getConstant().getConstantType() != Constant.ConstantType.EXTERNAL_METHOD)
            dot += "value: " + escapeString(node.getConstant().getValue());
          if (node.getConstant().getFuzzyLevel() > 0)
            dot += "fuzzy level: " + node.getConstant().getFuzzyLevel() + "\n";
          dot += "\"]";*/
          dot += " [label=<<table border=\"0\">";
          dot += "<tr><td colspan=\"2\">" + escapeHtml(node.getIdentifier()) + "</td></tr>";
          dot += "<tr><td>&nbsp;</td></tr>";
          // Omit the output of LOCAL_ANONYMOUS_CONSTANT -> no valuable information
          if (node.getConstant().getConstantType() != Constant.ConstantType.LOCAL_ANONYMOUS_CONSTANT)
            dot += "<tr><td>const type:</td><td>" + node.getConstant().getConstantType().toString() + "</td></tr>";
          dot += "<tr><td>variable type:</td><td>" + node.getConstant().getVarTypeDescription() + "</td></tr>";
          if (node.getConstant().getIdentifier() != null)
            dot += "<tr><td>name:</td><td>" + escapeHtml(node.getConstant().getIdentifier()) + "</td></tr>";
          // Omit the value output for external methods -> it is already written in the codeline
          if (node.getConstant().getConstantType() != Constant.ConstantType.EXTERNAL_METHOD &&
              node.getConstant().getConstantType() != Constant.ConstantType.NATIVE_METHOD)
            dot += "<tr><td>value:</td><td>" + escapeHtml(node.getConstant().getValue()) + "</td></tr>";
          if (node.getConstant().getFuzzyLevel() > 0 &&
              node.getConstant().getConstantType() != Constant.ConstantType.EXTERNAL_METHOD)
            dot += "<tr><td>fuzzy level:</td><td>" + node.getConstant().getFuzzyLevel() + "</td></tr>";
          dot += "</table>>]";
        }

        Table<String, String, Set<SliceNode>> linksFrom = node.getLinksFrom();
        for (Table.Cell<String, String, Set<SliceNode>> link : linksFrom.cellSet()) { // iterate over all key pairs
          for (SliceNode linkNodes : link.getValue()) { // all nodes having the same link, i.e. <p1, p1>
            links += "\"" + escapeString(linkNodes.getIdentifier()) + "\" -> \"" + escapeString(node.getIdentifier()) + "\"";
            String color = (!linkNodes.getMethod().equals(node.getMethod())) ? "color=indianred, " : "";
            String arrowDir = (isBackwardSlice ? "dir=back, " : "");
            //String color = (!linkNodes.getMethod().equals(node.getMethod())) ? "color=indianred, ltail=\"cluster_" + linkNodes.getMethod().hashCode() + "\", " : "";
            //links += "[" + color + "dir=back, label=\"" + link.getColumnKey() + " : " + link.getRowKey() + "\"]";
            if (isBackwardSlice)
              links += "[" + color + arrowDir + "label=\"" + link.getColumnKey() + " &rarr; " + link.getRowKey() + "\"]";
            else
              links += "[" + color + arrowDir + "label=\"" + link.getRowKey() + " &rarr; " + link.getColumnKey() + "\"]";
            links += ";\n";
          }
        }

        dot += " "; // space for next node
      }
      dot += ";\n\t}\n"; // end node listing and current subgraph
      dot += links; // add all links
    }

    try {

      File dotFile = new File(ConfigHandler.getInstance().getConfigValue(ConfigKeys.ANALYSIS_REPORT_FOLDER) +
          File.separator + dotName + ".dot");
      FileUtils.writeStringToFile(dotFile, generateDotGraph(dot, slicingPattern.toString()), "UTF-8", false);
      String outputFormat = ConfigHandler.getInstance().getConfigValue(ConfigKeys.ANALYSIS_SLICEGRAPH_OUTPUTFORMAT);
      ProcessBuilder builder = new ProcessBuilder(ConfigHandler.getInstance().getConfigValue(ConfigKeys.ANALYSIS_SLICEGRAPH_DOTEXECUTABLE),
          "-T" + outputFormat, dotFile.getAbsolutePath(), "-o" + dotFile.getParent() + File.separator + dotName + "." + outputFormat);
      builder.redirectErrorStream(true);
      Process process = builder.start();
      process.waitFor();
      FileUtils.deleteQuietly(dotFile);
    } catch (IOException | InterruptedException e) {
      e.printStackTrace();
    }
  }

  private String generateDotGraph(String graph, String graphLabel) {
    String head = "digraph G {\n";
    //head += "graph [ dpi = 150 ];\n";
    head += "ranksep=\"1.5 equally\"\n"; // Minimum vertical distance between nodes of different rank
    head += "compound=true;\n"; // Allow edges between clusters
    head += "label=\"" + graphLabel + "\";\n";
    //head += "nodesep = 1.25;"; // Minimum space between two adjacent nodes in the same rank (inches)
    //head += "edge [style=\"setlinewidth(3)\"];";
    String foot = "\n}";

    return head + graph + foot;
  }

  private static String escapeString(String original) {
    if (original == null)
      original = "";
    return original.replace("\"", "\\\"");
  }

  private static String escapeHtml(String original) {
    if (original == null)
      original = "";

    // Against https://www.graphviz.org/doc/info/shapes.html#html escaping " does not work and is not necessary.
    return original.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
  }
}
