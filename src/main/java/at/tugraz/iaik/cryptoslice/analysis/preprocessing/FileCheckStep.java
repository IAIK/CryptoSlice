package at.tugraz.iaik.cryptoslice.analysis.preprocessing;

import at.tugraz.iaik.cryptoslice.analysis.Analysis;
import at.tugraz.iaik.cryptoslice.analysis.AnalysisException;
import at.tugraz.iaik.cryptoslice.analysis.Step;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;

// Performs sanity checks on a given file before analysis
public class FileCheckStep extends Step {
  public FileCheckStep(boolean enabled) {
    this.name = "Check APK";
    this.enabled = enabled;
  }

  @Override
  public boolean doProcessing(Analysis analysis) throws AnalysisException {
    return isApkFile(analysis.getApp().getApkFile());
  }

  private boolean isApkFile(File apk) {
    try (FileInputStream fis = new FileInputStream(apk)) {
      if (apk.length() <= 2) {
        LOGGER.info("File too small. Aborting.");
        return false;
      }

      if (!apk.canRead()) {
        LOGGER.info("File not readable. Aborting.");
        return false;
      }

      byte[] fileHead = new byte[8];
      int read = fis.read(fileHead);
      if (read <= 2) {
        LOGGER.info("Could not read file: "+apk.getName()+". Aborting.");
        return false;
      }

      if (fileHead[0] != 'P' || fileHead[1] != 'K') {
        LOGGER.info("Magic bytes do not match! Aborting.");
        return false;
      }
    } catch (IOException e) {
      LOGGER.info("Could not check file, aborting. Message: "+e.getMessage());
      return false;
    }

    return true;
  }
}
