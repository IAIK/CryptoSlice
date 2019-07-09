package at.tugraz.iaik.cryptoslice.analysis;

import at.tugraz.iaik.cryptoslice.application.Application;
import at.tugraz.iaik.cryptoslice.utils.config.ConfigHandler;
import at.tugraz.iaik.cryptoslice.utils.config.ConfigKeys;
import org.apache.commons.io.FileUtils;

// Delete all files generated during the analysis
public class DeleteFilesStep extends Step {
  public DeleteFilesStep(boolean enabled) {
    this.name = "Cleanup analysis files";
    this.enabled = enabled;
  }

  @Override
  public boolean doProcessing(Analysis analysis) throws AnalysisException {
    if (ConfigHandler.getInstance().getBooleanConfigValue(ConfigKeys.ANALYSIS_KEEP_FILES)) {
      LOGGER.debug("Keeping all generated files in 'bytecode' directory.");
    } else {
      LOGGER.debug("Cleaning generated files from 'bytecode' directory");

      Application app = analysis.getApp();

      // Directory may be null if, eg. the file magic does not match and nothing was unpacked
      if (app != null && app.getAppWorkingDirectory() != null)
        FileUtils.deleteQuietly(app.getAppWorkingDirectory());
    }

    return true;
  }
}
