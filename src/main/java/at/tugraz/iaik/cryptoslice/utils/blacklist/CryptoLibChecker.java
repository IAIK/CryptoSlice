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

public class CryptoLibChecker extends XMLDataSource<BlacklistEntry> {
  private boolean filterLibs = false;
  private Set<BlacklistEntry> blacklistEntries = null;

  private static class CryptoLibCheckerHolder {
    private static final CryptoLibChecker INSTANCE = new CryptoLibChecker();
  }

  public static CryptoLibChecker getInstance() {
    return CryptoLibCheckerHolder.INSTANCE;
  }

  private CryptoLibChecker() {
    ConfigHandler conf = ConfigHandler.getInstance();

    this.dataFile = conf.getConfigValue(ConfigKeys.DATASOURCE_CRYPTO_LIBRARIES);
    this.schemaFile = conf.getConfigValue(ConfigKeys.DATASOURCE_BLACKLIST_SCHEMA);

    filterLibs = ConfigHandler.getInstance().getBooleanConfigValue(ConfigKeys.ANALYSIS_FILTER_CRYPTOLIBS);
    if (!filterLibs)
      return;

    // Read in the ad networks (only if filtering is activated)
    blacklistEntries = this.getData();
  }

  @Override
  protected Set<BlacklistEntry> doParse(Document doc) {
    Set<BlacklistEntry> blacklistEntries = new TreeSet<BlacklistEntry>();
    NodeList libs = doc.getElementsByTagName("exclude");
    if (libs != null) {
      for (int nodeIndex = 0; nodeIndex < libs.getLength(); nodeIndex++) {
        Element libNode = (Element) libs.item(nodeIndex);
        Attr name = libNode.getAttributeNode("path-fragment");

        if (name != null && !name.getValue().isEmpty())
          blacklistEntries.add(new BlacklistEntry(name.getValue().replace("/", File.separator)));
      }
    }

    return blacklistEntries;
  }

  public boolean containsCryptoLib(String absolutePath) {
    // If the crypto lib filter is disabled, we assume that there are no crypto libs at all
    if (!filterLibs)
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
