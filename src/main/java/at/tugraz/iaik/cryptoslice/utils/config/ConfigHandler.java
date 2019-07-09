package at.tugraz.iaik.cryptoslice.utils.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.HashSet;
import java.util.Properties;

public class ConfigHandler {
  private static final Logger LOGGER = LoggerFactory.getLogger(ConfigHandler.class);
  private final Properties settings = new Properties();

  private static class ConfigHandlerHolder {
    private static final ConfigHandler INSTANCE = new ConfigHandler();
  }

  public static ConfigHandler getInstance() {
    return ConfigHandlerHolder.INSTANCE;
  }

  private ConfigHandler() {
    try {
      readFromFile();
      validate();
    } catch (Exception e) {
      LOGGER.error(e.getMessage());
    }
  }

  private void readFromFile() throws IOException {
    // Assume that the configuration is in the local directory
    setConfigValue(ConfigKeys.DIRECTORY_HOME, System.getProperty("user.dir"));
    String configPath = getConfigValue(ConfigKeys.DIRECTORY_HOME) + File.separator + "conf" + File.separator + "cryptoslice.conf";

    try (FileInputStream fis = new FileInputStream(configPath)) {
      LOGGER.info("Loading configuration from " + configPath);
      settings.load(fis);
    }
  }

  private void validate() {
    LOGGER.info("Validating configuration paths...");

    boolean foundErrors = false;

    // Require a DIRECTORY_APPS setting in the config file
    /*if (!settings.containsKey(ConfigKeys.DIRECTORY_APPS.toString())) {
      LOGGER.error("No 'apps' directory configured!");
      foundErrors = true;
    }*/

    // Check all configuration file directives
    HashSet<Object> keysInConfigFile = new HashSet<Object>(settings.keySet());
    for (Object keyInConfigFile : keysInConfigFile) {
      String entry = (String) keyInConfigFile;
      try {
        // Check all directory listings for existance
        if (entry.startsWith("directory.")) {
          File f = new File(settings.getProperty(entry));
          if (!f.exists())
            f.mkdirs();

          if (!f.exists() || !f.isDirectory() || !f.canRead()) {
            LOGGER.error(entry + "=" + settings.getProperty(entry) + ": Directory does not exist or is not readable!");
            foundErrors = true;
          }
        }
      } catch (IllegalArgumentException e) {
        LOGGER.warn("Problem validating config: " + e.getMessage());
      }
    }

    // Also when using default values, the bytecode directory has to exist
    if (!settings.containsKey(ConfigKeys.DIRECTORY_BYTECODE.toString())) {
      File d = new File(getConfigValue(ConfigKeys.DIRECTORY_HOME) +
          File.separator + getConfigValue(ConfigKeys.DIRECTORY_BYTECODE));
      d.mkdirs();
    }

    if (foundErrors) {
      throw new RuntimeException("Found errors in the configuration. Aborting.");
    }
  }

  public String getConfigValue(ConfigKeys key) {
    return this.getConfigValue(key, key.getDefaultString());
  }

  public String getConfigValue(ConfigKeys key, String defaultValue) {
    return settings.getProperty(key.toString(), defaultValue);
  }

  public void setConfigValue(ConfigKeys key, String value) {
    settings.setProperty(key.toString(), String.valueOf(value));
  }

  public int getIntConfigValue(ConfigKeys key) {
    return this.getIntConfigValue(key, key.getDefaultInteger());
  }

  public int getIntConfigValue(ConfigKeys key, int defaultValue) {
    String r = settings.getProperty(key.toString());
    if (r != null)
      return Integer.parseInt(r);

    return defaultValue;
  }

  public boolean getBooleanConfigValue(ConfigKeys key) {
    return this.getBooleanConfigValue(key, key.getDefaultBoolean());
  }

  public boolean getBooleanConfigValue(ConfigKeys key, boolean defaultValue) {
    String r = settings.getProperty(key.toString());
    if (r != null)
      return Boolean.parseBoolean(r);

    return defaultValue;
  }
}
