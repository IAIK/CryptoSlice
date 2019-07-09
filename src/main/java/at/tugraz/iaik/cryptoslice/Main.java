package at.tugraz.iaik.cryptoslice;

import at.tugraz.iaik.cryptoslice.utils.PermissionMapLoader;
import at.tugraz.iaik.cryptoslice.utils.blacklist.AdChecker;
import at.tugraz.iaik.cryptoslice.utils.blacklist.CryptoLibChecker;
import at.tugraz.iaik.cryptoslice.utils.config.ConfigHandler;
import at.tugraz.iaik.cryptoslice.utils.config.ConfigKeys;
import org.apache.commons.io.FileUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.util.Collection;
import java.util.LinkedList;
import java.util.concurrent.TimeUnit;

public class Main {
  private static final Logger LOGGER = LoggerFactory.getLogger(Main.class);
  private static ConfigHandler conf = null;

  public static void main(String[] args) {
    try {
      conf = ConfigHandler.getInstance();
      prepare();

      // You can specify one app/directory but you do not have to
      File apkPath = null;
      if (args.length == 1)
        apkPath = new File(args[0]);
      else if (args.length > 1) {
        System.out.println("Usage: java -jar cryptoslice.jar [file/directory]");
        System.exit(0);
      }

      // Collect one or multiple .apk files for further analysis
      LinkedList<File> apks = collectApks(apkPath);
      startAnalysis(apks);

    } catch (Exception e) {
        LOGGER.error(e.getMessage());
        e.printStackTrace();
    }
  }

  private static LinkedList<File> collectApks(File path) {
    LinkedList<File> apks = new LinkedList<File>();

    // If no path is given, take the default/configured apps directory
    if (path == null)
      path = new File(conf.getConfigValue(ConfigKeys.DIRECTORY_APPS));

    path.mkdirs();
    if (!path.exists()) {
      LOGGER.error("File or directory does not exist: " + path);
      return apks;
    }

    // Fetch .apk files recursively
    if (path.isDirectory()) {
      Collection<File> fc = FileUtils.listFiles(path, new String[]{"apk"}, true);
      apks = new LinkedList<File>(fc);

      LOGGER.info("Read " + apks.size() + " files from directory: " + path);
    } else if (path.isFile()) {
      apks.add(path);
    }

    if (apks.isEmpty()) {
      LOGGER.error("Found no APK files to analyze!");
      System.exit(-1);
    }

    return apks;
  }

  private static void prepare() {
    // Initialize the Blacklist handlers
    AdChecker.getInstance();
    CryptoLibChecker.getInstance();
    PermissionMapLoader.getInstance();

    // Always take the newest framework file from Apktool -> delete it
    FileUtils.deleteQuietly(new File(conf.getConfigValue(ConfigKeys.DIRECTORY_BYTECODE) + File.separator + "1.apk"));

    // Create reports folder if reporting is enabled
    if (ConfigHandler.getInstance().getBooleanConfigValue(ConfigKeys.ANALYSIS_DO_REPORT)) {
      new File(conf.getConfigValue(ConfigKeys.ANALYSIS_REPORT_FOLDER)).mkdirs();
    }
  }

  private static void startAnalysis(LinkedList<File> apks) {
    // Initialize MultiThreading and queue
    int corePoolSize = Runtime.getRuntime().availableProcessors();
    if (corePoolSize > 1) corePoolSize--;
    int numThreads = conf.getIntConfigValue(ConfigKeys.MULTITHREADING_THREADS, corePoolSize);
    if (!conf.getBooleanConfigValue(ConfigKeys.MULTITHREADING_ENABLED))
      numThreads = 1;

    // Create executor and submit jobs
    CSThreadPoolExecutor executor = new CSThreadPoolExecutor(apks, numThreads, numThreads, 5, TimeUnit.SECONDS);
    executor.allowCoreThreadTimeOut(true);

    // Tell the executor to shutdown afterwards
    executor.shutdown();
    boolean b = true;
    try {
      b = executor.awaitTermination(Long.MAX_VALUE, TimeUnit.DAYS); // timeout should not occur
    } catch (InterruptedException e) {
      LOGGER.error("Got interrupted while waiting for analyses to finish, this should not happen.", e);
    }

    if (!b)
      LOGGER.error("Got a timeout while waiting for analyses to finish, this should not happen.");

    executor.printStats();
  }
}
