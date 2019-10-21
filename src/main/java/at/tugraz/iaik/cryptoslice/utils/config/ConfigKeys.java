package at.tugraz.iaik.cryptoslice.utils.config;

public enum ConfigKeys {
  /**
   * Decompile the APK to SMALI code.
   */
  ANALYSIS_DECOMPILE_APK("analysis.decompileapk.enable", true),
  /**
   * Do not re-decompile already decompiled APK files.
   */
  ANALYSIS_DECOMPILE_OMITEXISTING("analysis.decompileapk.omitexisting", true),
  /**
   * Whether we should do heuristic analysis.
   */
  ANALYSIS_DO_HEURISTIC("analysis.heuristic.enable", false),
  /**
   * Output a summary report when analysis terminates.
   */
  ANALYSIS_DO_REPORT("analysis.report.enable", true),
  /**
   * Whether to print all sliced paths to a file.
   */
  ANALYSIS_DO_SAVE_SLICE_PATHS("analysis.slicing.pathlogger", false),
  /**
   * Whether to automatically analyse the results from slicing.
   */
  ANALYSIS_DO_SLICEANALYSIS("analysis.slicing.sliceanalysis", true),
  /**
   * Whether we should do static slicing.
   */
  ANALYSIS_DO_SLICING("analysis.slicing.enable", true),
  /**
   * Globally enable/disable backward slicing.
   */
  ANALYSIS_DO_SLICING_BACKWARD("analysis.slicing.backward", true),
  /**
   * Globally enable/disable forward slicing.
   */
  ANALYSIS_DO_SLICING_FORWARD("analysis.slicing.forward", true),
  /**
   * Perform a URL scan.
   */
  ANALYSIS_DO_URLSCAN("analysis.urlscan.enable", false),
  /**
   * Perform a scan for secrets.
   */
  ANALYSIS_DO_SECRETSCAN("analysis.secretscan.enable", false),
  /**
   * Whether to extract APK content.
   */
  ANALYSIS_EXTRACT_APK("analysis.extractapk.enable", false),
  /**
   * Filter out AdNetworks while parsing Smali files.
   */
  ANALYSIS_FILTER_ADNETWORKS("analysis.filter.adnetworks", "false"),
  /**
   * Filter out crypto libraries while parsing Smali files.
   */
  ANALYSIS_FILTER_CRYPTOLIBS("analysis.filter.cryptolibs", "false"),
  /**
   * Retrieve whether we should remove the unpacked/analyzed content on completion.
   */
  ANALYSIS_KEEP_FILES("analysis.keep.files", false),
  /**
   * Match Manifest permissions with API calls.
   */
  ANALYSIS_MATCH_APICALLS("analysis.match.apicalls", "false"),
  /**
   * The folder where created reports are located.
   */
  ANALYSIS_REPORT_FOLDER("analysis.report.folder", "reports"),
  /**
   * The path to the XML report template.
   */
  ANALYSIS_REPORT_TEMPLATE("analysis.report.template", "conf/report.stg"),
  /**
   * Whether to create a slice graph based on the previously obtained slicing results.
   */
  ANALYSIS_SLICEGRAPH_CREATE("analysis.slicegraph.create", false),
  /**
   * The path to the Graphviz dot executable.
   */
  ANALYSIS_SLICEGRAPH_DOTEXECUTABLE("analysis.slicegraph.dotexecutable", "/usr/bin/dot"),
  /**
   * The output format used by Graphviz dot.
   */
  ANALYSIS_SLICEGRAPH_OUTPUTFORMAT("analysis.slicegraph.outputformat", "svg"),
  /**
   * Whether to add JMP instructions to the slice tree (cosmetic issue)
   */
  ANALYSIS_SLICING_INCLUDE_JMP("analysis.slicing.includejmpintree", true),
  /**
   * Max fuzzy level while slicing.
   */
  ANALYSIS_SLICING_MAXFUZZYLEVEL("analyis.slicing.maxfuzzylevel", 12),
  /**
   * Maximum amount of registers to track.
   */
  ANALYSIS_SLICING_MAXRSCOUNT("analyis.slicing.maxrscount", 50000),
  /**
   * Whether to backtrace constants (previously obtained by slicing)
   */
  ANALYSIS_TRACE_SLICINGCONST("analysis.trace.slicingconst", false),
  /**
   * The file that provides the ad-network definitions.
   */
  DATASOURCE_AD_NETWORKS("datasource.adnetworks", "conf/blacklist-adnetworks.xml"),
  /**
   * The file that provides the schema to validate the blacklist definitions.
   */
  DATASOURCE_BLACKLIST_SCHEMA("datasource.blacklist.schema", "conf/schema/blacklist.xsd"),
  /**
   * The file that provides the crypto libraries definitions.
   */
  DATASOURCE_CRYPTO_LIBRARIES("datasource.cryptolibs", "conf/blacklist-cryptolibs.xml"),
  /**
   * Heuristic pattern location.
   */
  DATASOURCE_HEURISTIC_PATTERNS("datasource.heuristic", "conf/heuristic-patterns.xml"),
  /**
   * Heuristic pattern validation schema.
   */
  DATASOURCE_HEURISTIC_SCHEMA("datasource.heuristic.schema", "conf/schema/heuristic-patterns.xsd"),
  /**
   * The file that provides a mapping of permissions and API calls.
   */
  DATASOURCE_PERMISSIONMAP("datasource.permissionmap", "conf/permission-map.txt"),
  /**
   * Slicing pattern location.
   */
  DATASOURCE_SLICING_PATTERNS("datasource.slicing","conf/slicing-patterns.xml"),
  /**
   * Slicing pattern validation schema.
   */
  DATASOURCE_SLICING_SCHEMA("datasource.slicing.schema","conf/schema/slicing-patterns.xsd"),
  /**
   * A directory from which .apk files are loaded for mass investigation.
   */
  DIRECTORY_APPS("directory.apps", "apps"),
  /**
   * The directory where smali code is stored during analysis.
   */
  DIRECTORY_BYTECODE("directory.bytecode", "bytecode"),
  /**
   * The name of the folder where the unpacked raw .apk content is stored.
   */
  DIRECTORY_BYTECODE_APK("subdir.bytecode.apk", "apk"),
  /**
   * The name of the folder where the decompiled content (smali, Manifest) is stored.
   */
  DIRECTORY_BYTECODE_DECOMPILED("subdir.content.decompiled", "decompiled"),
  /**
   * The directory from which all other paths are considered relative.
   * Is set at runtime.
   */
  DIRECTORY_HOME("directory.home"),
  /**
   * Whether to enable concurrent processing of multiple apps.
   */
  MULTITHREADING_ENABLED("multithreading.enable", false),
  /**
   * If enabled, the amount of threads to use. The default value is the
   * number of available processor cores.
   */
  MULTITHREADING_THREADS("multithreading.threads");

  private final String name;
  private String defaultString;
  private boolean defaultBoolean;
  private int defaultInteger;

  ConfigKeys(String name) {
    this.name = name;
  }

  ConfigKeys(String name, String defaultValue) {
    this.name = name;
    this.defaultString = defaultValue;
  }

  ConfigKeys(String name, boolean defaultValue) {
    this.name = name;
    this.defaultBoolean = defaultValue;
  }

  ConfigKeys(String name, int defaultValue) {
    this.name = name;
    this.defaultInteger = defaultValue;
  }

  public String getDefaultString() {
    return defaultString;
  }

  public boolean getDefaultBoolean() {
    return defaultBoolean;
  }

  public int getDefaultInteger() {
    return defaultInteger;
  }

  public String toString() {
    return name;
  }
}
