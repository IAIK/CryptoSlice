package at.tugraz.iaik.cryptoslice.analysis.preprocessing;

import at.tugraz.iaik.cryptoslice.analysis.Analysis;
import at.tugraz.iaik.cryptoslice.analysis.AnalysisException;
import at.tugraz.iaik.cryptoslice.analysis.Step;
import at.tugraz.iaik.cryptoslice.application.Application;
import at.tugraz.iaik.cryptoslice.utils.config.ConfigHandler;
import at.tugraz.iaik.cryptoslice.utils.config.ConfigKeys;
import com.google.common.hash.HashCode;
import com.google.common.hash.Hashing;
import com.google.common.io.Files;

import java.io.File;
import java.io.IOException;

// Creates the folder structure necessary for further analysis
public class SetupFileSystemStep extends Step {
  public SetupFileSystemStep(boolean enabled) {
    this.name = "Create folders";
    this.enabled = enabled;
  }

  @Override
  public boolean doProcessing(Analysis analysis) throws AnalysisException {
    ConfigHandler conf = ConfigHandler.getInstance();
    Application app = analysis.getApp();
    File apk = app.getApkFile();

    // Calculate the file's hash
    HashCode apkHash;
    try {
      apkHash = Files.asByteSource(apk).hash(Hashing.murmur3_128());
    } catch(IOException ie) {
      throw new AnalysisException("Failure while reading in the .apk file", ie);
    }

    // Create all needed directories
    File bytecodePath = new File(conf.getConfigValue(ConfigKeys.DIRECTORY_BYTECODE));
    app.setBytecodeDirectory(bytecodePath);

    File appWorkingDir = new File(bytecodePath.getAbsolutePath() + File.separator + app.getApplicationName() + "_" + apkHash.toString());
    app.setAppWorkingDirectory(appWorkingDir);
    LOGGER.debug("The app working directory will be at: " + appWorkingDir.getAbsolutePath());

    // Directory for decompiled resources
    File decompiledContentDir = new File(appWorkingDir.getAbsolutePath() + File.separator + conf.getConfigValue(ConfigKeys.DIRECTORY_BYTECODE_DECOMPILED));
    decompiledContentDir.mkdirs();
    app.setBytecodeDecompiledDirectory(decompiledContentDir);
    LOGGER.debug("The decompiled content will be at: " + decompiledContentDir.getAbsolutePath());

    // Directory where the apk is unpacked to
    File apkContentDir = new File(appWorkingDir.getAbsolutePath() + File.separator + conf.getConfigValue(ConfigKeys.DIRECTORY_BYTECODE_APK));
    apkContentDir.mkdirs();
    app.setBytecodeApkDirectory(apkContentDir);
    LOGGER.debug("The raw .apk content will be at: " + apkContentDir.getAbsolutePath());

    // Set smali directory of the application
    File smaliDirectory = new File(decompiledContentDir.getAbsolutePath() + File.separator + "smali");
    smaliDirectory.mkdirs();
    app.setSmaliDirectory(smaliDirectory);
    LOGGER.debug("The smali files will be at: " + smaliDirectory.getAbsolutePath());

    return true;
  }
}
