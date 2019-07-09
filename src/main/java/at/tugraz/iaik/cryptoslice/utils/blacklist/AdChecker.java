package at.tugraz.iaik.cryptoslice.utils.blacklist;

import at.tugraz.iaik.cryptoslice.utils.config.ConfigHandler;
import at.tugraz.iaik.cryptoslice.utils.config.ConfigKeys;
import at.tugraz.iaik.cryptoslice.utils.xml.XMLDataSource;
import org.w3c.dom.Attr;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import java.io.File;
import java.util.Set;
import java.util.TreeSet;

public class AdChecker extends XMLDataSource<BlacklistEntry> {
  private boolean filterAds = false;
  private Set<BlacklistEntry> blacklistEntries = null;

  private static class AdCheckerHolder {
    private static final AdChecker INSTANCE = new AdChecker();
  }

  public static AdChecker getInstance() {
    return AdCheckerHolder.INSTANCE;
  }

  private AdChecker() {
    ConfigHandler conf = ConfigHandler.getInstance();

    this.dataFile = conf.getConfigValue(ConfigKeys.DATASOURCE_AD_NETWORKS);
    this.schemaFile = conf.getConfigValue(ConfigKeys.DATASOURCE_BLACKLIST_SCHEMA);

    filterAds = ConfigHandler.getInstance().getBooleanConfigValue(ConfigKeys.ANALYSIS_FILTER_ADNETWORKS);
    if (!filterAds)
      return;

    // Read in the ad networks (only if filtering is activated)
    blacklistEntries = this.getData();
  }

  @Override
  protected Set<BlacklistEntry> doParse(Document doc) {
    Set<BlacklistEntry> blacklistEntries = new TreeSet<BlacklistEntry>();
    NodeList adNodes = doc.getElementsByTagName("exclude");
    if (adNodes != null) {
      for (int nodeIndex = 0; nodeIndex < adNodes.getLength(); nodeIndex++) {
        Element adNode = (Element) adNodes.item(nodeIndex);
        Attr name = adNode.getAttributeNode("path-fragment");

        if (name != null && !name.getValue().isEmpty())
          blacklistEntries.add(new BlacklistEntry(name.getValue().replace("/", File.separator)));
      }
    }

    return blacklistEntries;
  }

  public boolean containsAd(String absolutePath) {
    // If the ad filter is disabled, we assume that there are no ads at all
    if (!filterAds)
      return false;

    // Make sure the path ends with /
    if (absolutePath.charAt(absolutePath.length()-1) != File.separatorChar)
      absolutePath += File.separator;

    for (BlacklistEntry network : blacklistEntries) {
      if (absolutePath.contains(network.getPath())) {
        return true;
      }
    }

    return false;
  }
}
