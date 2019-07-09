package at.tugraz.iaik.cryptoslice.utils.xml;

import at.tugraz.iaik.cryptoslice.analysis.heuristic.HPattern;
import at.tugraz.iaik.cryptoslice.utils.config.ConfigHandler;
import at.tugraz.iaik.cryptoslice.utils.config.ConfigKeys;
import org.w3c.dom.Attr;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import java.util.*;

public class XMLHPatternSource extends XMLDataSource<HPattern> {
  private Map<String, Set<HPattern>> patternsFiltered = new HashMap<String, Set<HPattern>>();

  private static class XMLHPatternSourceHolder {
    private static final XMLHPatternSource INSTANCE = new XMLHPatternSource();
  }

  public static XMLHPatternSource getInstance() {
    return XMLHPatternSourceHolder.INSTANCE;
  }

  private XMLHPatternSource() {
    ConfigHandler conf = ConfigHandler.getInstance();

    this.dataFile = conf.getConfigValue(ConfigKeys.DATASOURCE_HEURISTIC_PATTERNS);
    this.schemaFile = conf.getConfigValue(ConfigKeys.DATASOURCE_HEURISTIC_SCHEMA);

    boolean doSlicing = ConfigHandler.getInstance().getBooleanConfigValue(ConfigKeys.ANALYSIS_DO_HEURISTIC);
    if (!doSlicing)
      return;

    // Read in the patterns (only if heuristic is enabled)
    Set<HPattern> patterns = this.getData();

    // Group the patterns by their type
    for (HPattern pattern : patterns) {
      if (!patternsFiltered.containsKey(pattern.getType()))
        patternsFiltered.put(pattern.getType(), new TreeSet<HPattern>());

      patternsFiltered.get(pattern.getType()).add(pattern);
    }
  }

  @Override
  protected Set<HPattern> doParse(Document doc) {
    Set<HPattern> patterns = new TreeSet<HPattern>();
    NodeList patternNodes = doc.getElementsByTagName("heuristic-pattern");

    if (patternNodes != null && patternNodes.getLength() > 0) {
      LOGGER.trace("Found " + patternNodes.getLength() + " nodes of type heuristic-pattern");
      for (int nodeIndex = 0; nodeIndex < patternNodes.getLength(); nodeIndex++) {
        Element patternNode = (Element) patternNodes.item(nodeIndex);

        // Obtain all attributes
        Attr pattern = patternNode.getAttributeNode("pattern");
        Attr type = patternNode.getAttributeNode("type");
        Attr desc = patternNode.getAttributeNode("description");
        Attr enabled = patternNode.getAttributeNode("enabled");
        if (pattern != null && type != null && desc != null && enabled != null) {
          //LOGGER.debug("Adding pattern " + nodeIndex);
          HPattern p = new HPattern(pattern.getValue(), type.getValue(), desc.getValue());
          p.setEnabled(Boolean.parseBoolean(enabled.getValue()));
          patterns.add(p);
        } else {
          LOGGER.warn("Something went wrong parsing at heuristic pattern " + nodeIndex);
        }
      }
    } else {
      LOGGER.warn("No heuristic patterns found in file" + this.dataFile);
    }
    LOGGER.trace("Loaded " + patterns.size() + " heuristic patterns.");

    return patterns;
  }

  public Map<String, Set<HPattern>> getPatterns() {
    return patternsFiltered;
  }
}
