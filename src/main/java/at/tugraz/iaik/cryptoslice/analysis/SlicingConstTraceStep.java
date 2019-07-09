package at.tugraz.iaik.cryptoslice.analysis;

import at.tugraz.iaik.cryptoslice.analysis.slicing.SliceNode;
import at.tugraz.iaik.cryptoslice.analysis.slicing.SliceTree;
import at.tugraz.iaik.cryptoslice.analysis.slicing.SlicingPattern;
import at.tugraz.iaik.cryptoslice.application.methods.Method;
import at.tugraz.iaik.cryptoslice.utils.FileList;
import at.tugraz.iaik.cryptoslice.utils.config.ConfigHandler;
import at.tugraz.iaik.cryptoslice.utils.config.ConfigKeys;
import com.google.common.collect.Multimap;
import com.google.common.collect.Table;
import org.apache.commons.io.FileUtils;

import java.io.File;
import java.io.IOException;
import java.util.Map;
import java.util.Set;

// Prints slicing constants in a stacktrace like format
public class SlicingConstTraceStep extends Step {
  public SlicingConstTraceStep(boolean enabled) {
    this.name = "Constant trace";
    this.enabled = enabled;
  }

  @Override
  public boolean doProcessing(Analysis analysis) throws AnalysisException {
    Table<SlicingPattern, Integer, SliceTree> allSliceTrees = analysis.getSliceTrees();
    String out = "";

    // Separate per pattern
    for (Map.Entry<SlicingPattern, Map<Integer, SliceTree>> pattern : allSliceTrees.rowMap().entrySet()) {
      SlicingPattern slicingPattern = pattern.getKey();
      Map<Integer, SliceTree> sliceTrees = pattern.getValue();

      out += slicingPattern.toString() + "\n";
      for (SliceTree tree : sliceTrees.values()) { // one tree per searchId
        Multimap<Method, SliceNode> sliceNodes = tree.getSliceNodes();

        for (SliceNode node : sliceNodes.values()) {
          if (node.getConstant() != null) {
            Map<String, Set<SliceNode>> traceNodes = node.getLinksFrom().column("const"); // in fact max. 1 node
            String refSmaliFile = node.getMethod().getSmaliClass().getFullClassName(false) + FileList.SMALI_FILES;

            out += "\n" + node.getConstant() + "\n";
            if (!traceNodes.isEmpty())
              out += " " + refSmaliFile + ":\n";

            // TODO: fix this!!
            /*
            while (!traceNodes.isEmpty()) {
              Map.Entry<String, Set<SliceNode>> traceNodeIterator = traceNodes.entrySet().iterator().next();
              String traceRegister = traceNodeIterator.getKey();

              // Taking always the first node of the Set can lead to cycles!!
              SliceNode traceNode = traceNodeIterator.getValue().iterator().next();

              String curSmaliFile = traceNode.getMethod().getSmaliClass().getFullClassName(false) + ".smali";
              if (!curSmaliFile.equals(refSmaliFile)) {
                out += " " + curSmaliFile + ":\n";
                refSmaliFile = curSmaliFile;
              }

              out += "   tracking " + traceRegister + " -> " + traceNode.getCodeLine() + "\n";
              traceNodes = traceNode.getLinksFrom().column(traceRegister);
            }*/
          }
        }
      }

      out += "\n\n"; // newlines before next pattern
    }

    // Only write an output file if there is something to write
    if (!allSliceTrees.isEmpty()) {
      File outfile = new File(ConfigHandler.getInstance().getConfigValue(ConfigKeys.ANALYSIS_REPORT_FOLDER) +
          File.separator + analysis.getApp().getApplicationName() + ".txt");
      try {
        FileUtils.writeStringToFile(outfile, out, "UTF-8", false);
      } catch (IOException e) {
        e.printStackTrace();
      }
    }

    return true;
  }
}