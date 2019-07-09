package at.tugraz.iaik.cryptoslice.utils.xml;

import at.tugraz.iaik.cryptoslice.analysis.slicing.SlicingPattern;
import at.tugraz.iaik.cryptoslice.analysis.slicing.SlicingPatternBT;
import at.tugraz.iaik.cryptoslice.analysis.slicing.SlicingPatternFT;
import at.tugraz.iaik.cryptoslice.utils.config.ConfigHandler;
import at.tugraz.iaik.cryptoslice.utils.config.ConfigKeys;
import org.w3c.dom.Attr;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import java.util.HashSet;
import java.util.Set;

// Slicing patterns (backward/forward)
public class XMLTPatternSource extends XMLDataSource<SlicingPattern> {
  private Set<SlicingPattern> patterns = new HashSet<>();
  private boolean forwardPatternProvided = false;

  private static class XMLTPatternSourceHolder {
    private static final XMLTPatternSource INSTANCE = new XMLTPatternSource();
  }

  public static XMLTPatternSource getInstance() {
    return XMLTPatternSourceHolder.INSTANCE;
  }

  private XMLTPatternSource() {
    ConfigHandler conf = ConfigHandler.getInstance();

    this.dataFile = conf.getConfigValue(ConfigKeys.DATASOURCE_SLICING_PATTERNS);
    this.schemaFile = conf.getConfigValue(ConfigKeys.DATASOURCE_SLICING_SCHEMA);

    boolean doSlicing = ConfigHandler.getInstance().getBooleanConfigValue(ConfigKeys.ANALYSIS_DO_SLICING);
    if (!doSlicing)
      return;

    // Read in the patterns (only if slicing is enabled)
    this.patterns = this.getData();
  }

  @Override
  protected Set<SlicingPattern> doParse(Document doc) {
    Set<SlicingPattern> patterns = new HashSet<>();
    NodeList btPatternNodes = doc.getElementsByTagName("backtracking-pattern");
    NodeList ftPatternNodes = doc.getElementsByTagName("forwardtracking-pattern");
    boolean doBack = ConfigHandler.getInstance().getBooleanConfigValue(ConfigKeys.ANALYSIS_DO_SLICING_BACKWARD);
    boolean doForward = ConfigHandler.getInstance().getBooleanConfigValue(ConfigKeys.ANALYSIS_DO_SLICING_FORWARD);

    if (doBack) {
      if (btPatternNodes != null && btPatternNodes.getLength() > 0) {
        LOGGER.trace("Found " + btPatternNodes.getLength() + " nodes of type backtracking-pattern");
        for (int nodeIndex = 0; nodeIndex < btPatternNodes.getLength(); nodeIndex++) {
          Element patternNode = (Element) btPatternNodes.item(nodeIndex);

          // Obtain all attributes
          Attr pkg = patternNode.getAttributeNode("class");
          Attr method = patternNode.getAttributeNode("method");
          Attr desc = patternNode.getAttributeNode("description");
          Attr paramSpec = patternNode.getAttributeNode("parameters");
          Attr paramOfInterest = patternNode.getAttributeNode("interestingParameter");
          Attr enabled = patternNode.getAttributeNode("enabled");
          if (pkg != null && method != null && desc != null && enabled != null) {
            //LOGGER.debug("Adding pattern " + nodeIndex);
            SlicingPatternBT p = new SlicingPatternBT(pkg.getValue(), method.getValue(), paramSpec.getValue(),
                Integer.parseInt(paramOfInterest.getValue()), desc.getValue());
            p.setEnabled(Boolean.parseBoolean(enabled.getValue()));
            patterns.add(p);
          } else {
            LOGGER.warn("Something went wrong parsing at backtracking pattern " + nodeIndex);
          }
        }
      } else {
        LOGGER.debug("No backtracking patterns found in file" + this.dataFile);
      }
    }

    if (doForward) {
      if (ftPatternNodes != null && ftPatternNodes.getLength() > 0) {
        LOGGER.trace("Found " + ftPatternNodes.getLength() + " nodes of type forwardtracking-pattern");
        forwardPatternProvided = true;
        for (int nodeIndex = 0; nodeIndex < ftPatternNodes.getLength(); nodeIndex++) {
          Element patternNode = (Element) ftPatternNodes.item(nodeIndex);

          // Obtain all attributes
          Attr type = patternNode.getAttributeNode("type");
          Attr desc = patternNode.getAttributeNode("description");
          Attr enabled = patternNode.getAttributeNode("enabled");

          Attr pattern = patternNode.getAttributeNode("pattern");
          Attr pkg = patternNode.getAttributeNode("class");
          Attr method = patternNode.getAttributeNode("method");
          if (pattern != null && type != null && desc != null && enabled != null) {
            //LOGGER.debug("Adding pattern " + nodeIndex);
            SlicingPatternFT p = new SlicingPatternFT(pattern.getValue(), type.getValue(), desc.getValue());
            p.setEnabled(Boolean.parseBoolean(enabled.getValue()));
            patterns.add(p);
          } else if (pkg != null && method != null && type != null && desc != null && enabled != null) {
            //LOGGER.debug("Adding pattern " + nodeIndex);
            SlicingPatternFT p = new SlicingPatternFT(pkg.getValue(), method.getValue(), type.getValue(), desc.getValue());
            p.setEnabled(Boolean.parseBoolean(enabled.getValue()));
            patterns.add(p);
          } else {
            LOGGER.warn("Something went wrong parsing at forwardtracking pattern " + nodeIndex);
          }
        }
      } else {
        LOGGER.debug("No forward patterns found in file " + this.dataFile);
      }
    }

    LOGGER.trace("Loaded " + patterns.size() + " slicing patterns.");

    return patterns;
  }

  public boolean isForwardPatternProvided() { return forwardPatternProvided; }

  public Set<SlicingPattern> getPatterns() {
    return patterns;
  }
}
