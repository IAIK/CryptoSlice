package at.tugraz.iaik.cryptoslice.analysis;

import at.tugraz.iaik.cryptoslice.analysis.slicing.SliceNode;
import at.tugraz.iaik.cryptoslice.analysis.slicing.SliceTree;
import at.tugraz.iaik.cryptoslice.analysis.slicing.SlicingPattern;
import at.tugraz.iaik.cryptoslice.utils.PathFinder;
import at.tugraz.iaik.cryptoslice.utils.config.ConfigHandler;
import at.tugraz.iaik.cryptoslice.utils.config.ConfigKeys;
import com.google.common.collect.Table;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.File;
import java.util.Collections;
import java.util.List;
import java.util.Map;

public class PathLoggerStep extends Step {
  public PathLoggerStep(boolean enabled) {
    this.name = "Logging of Program Paths";
    this.enabled = enabled;
  }

  @Override
  public boolean doProcessing(Analysis analysis) throws AnalysisException {
    Table<SlicingPattern, Integer, SliceTree> allSliceTrees = analysis.getSliceTrees();
    if (allSliceTrees.isEmpty()) {
      return true;
    }

    DocumentBuilderFactory docFactory = DocumentBuilderFactory.newInstance();
    DocumentBuilder docBuilder;
    try {
      docBuilder = docFactory.newDocumentBuilder();
    } catch (ParserConfigurationException e) {
      e.printStackTrace();
      return false;
    }

    Document doc = docBuilder.newDocument();
    Element rootElement = doc.createElement("slicedApp");
    doc.appendChild(rootElement);
    rootElement.setAttribute("apkfile", analysis.getApp().getApplicationName());

    // Separate per pattern
    for (Map.Entry<SlicingPattern, Map<Integer, SliceTree>> pattern : allSliceTrees.rowMap().entrySet()) {
      SlicingPattern slicingPattern = pattern.getKey();
      Map<Integer, SliceTree> sliceTrees = pattern.getValue();

      // Create pattern element
      Element patternelement = doc.createElement("slicepattern");
      rootElement.appendChild(patternelement);
      patternelement.setAttribute("description", slicingPattern.getDescription());
      patternelement.setAttribute("type", slicingPattern.getSlicingType().toString());

      LOGGER.debug("Slicing pattern: " + slicingPattern.toString());

      for (SliceTree tree : sliceTrees.values()) { // one tree per searchId
        // Extract all paths to leafs from the slicetree
        List<List<SliceNode>> paths = PathFinder.extractAllPathsToLeafs(tree, tree.getStartNode());

        // Loop over all paths to leafs in the slice tree
        for (List<SliceNode> path : paths) {
          Element pathelement = doc.createElement("path");
          patternelement.appendChild(pathelement);

          Collections.reverse(path);
          //System.out.println("path:");

          for (SliceNode currentNode : path) {
            //System.out.println(currentNode.getCodeLine());

            Element nodeelement = doc.createElement("node");
            pathelement.appendChild(nodeelement);

            //Element codelineelem = doc.createElement("code");
            nodeelement.setTextContent(new String(currentNode.getCodeLine().getLine()));
            //nodeelement.appendChild(codelineelem);

            //currentNode.getCodeLine().getInstruction().getOpCode();

            nodeelement.setAttribute("lineNo", String.valueOf(currentNode.getCodeLine().getLineNr()));
            nodeelement.setAttribute("class", currentNode.getCodeLine().getSmaliClass().getFullClassName(true));
            nodeelement.setAttribute("method", currentNode.getMethod().getReadableJavaName());
          }
        }
      }
    }

    // Write the content into an XML file
    try {
      Transformer transformer = TransformerFactory.newInstance().newTransformer();
      transformer.setOutputProperty(OutputKeys.INDENT, "yes");
      transformer.setOutputProperty("{http://xml.apache.org/xslt}indent-amount", "2");
      DOMSource source = new DOMSource(doc);
      String filepath = ConfigHandler.getInstance().getConfigValue(ConfigKeys.ANALYSIS_REPORT_FOLDER) +
          File.separator + analysis.getApp().getApplicationName() + ".paths.xml";

      StreamResult result = new StreamResult(new File(filepath));
      transformer.transform(source, result);

      LOGGER.debug("Saved paths to file " + filepath);
    } catch (TransformerException e) {
      LOGGER.error("failed to save paths to file", e);
      e.printStackTrace();
    }

    return true;
  }
}
