package at.tugraz.iaik.cryptoslice.analysis;

import at.tugraz.iaik.cryptoslice.analysis.heuristic.HResult;
import at.tugraz.iaik.cryptoslice.analysis.heuristic.HeuristicSearchStep;
import at.tugraz.iaik.cryptoslice.analysis.nativecode.NativeCodeStep;
import at.tugraz.iaik.cryptoslice.analysis.preprocessing.*;
import at.tugraz.iaik.cryptoslice.analysis.slicing.SliceTree;
import at.tugraz.iaik.cryptoslice.analysis.slicing.SlicingPattern;
import at.tugraz.iaik.cryptoslice.analysis.slicing.SlicingStep;
import at.tugraz.iaik.cryptoslice.analysis.slicinganalysis.SliceAnalysisStep;
import at.tugraz.iaik.cryptoslice.application.Application;
import at.tugraz.iaik.cryptoslice.application.instructions.Constant;
import at.tugraz.iaik.cryptoslice.utils.config.ConfigHandler;
import at.tugraz.iaik.cryptoslice.utils.config.ConfigKeys;
import com.google.common.collect.HashBasedTable;
import com.google.common.collect.Table;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.Set;

public class Analysis {
  private static final Logger LOGGER = LoggerFactory.getLogger(Analysis.class);
  private static final List<Step> PREPROCESSING_STEPS = new ArrayList<>();
  private static final List<Step> ANALYSIS_STEPS = new ArrayList<>();
  private static final List<Step> CLEANUP_STEPS = new ArrayList<>();

  private Application app;
  private final List<AnalysisException> criticalExceptions = new ArrayList<>();
  private final List<AnalysisException> nonCriticalExceptions = new ArrayList<>();
  private Table<SlicingPattern, Integer, Set<Constant>> sliceConstants = HashBasedTable.create();
  private Table<SlicingPattern, Integer, SliceTree> sliceTrees = HashBasedTable.create();
  private List<HResult> heuristicResults = new ArrayList<>();
  private final AnalysisReport report = new AnalysisReport();

  static {
    PREPROCESSING_STEPS.addAll(buildPreprocessingSteps());
    ANALYSIS_STEPS.addAll(buildAnalysisSteps());
    CLEANUP_STEPS.addAll(buildCleanupSteps());
  }

  public Analysis(Application app) {
    this.app = app;
  }

  private static List<Step> buildPreprocessingSteps() {
    List<Step> processingSteps = new ArrayList<>();
    processingSteps.add(new FileCheckStep(true));
    processingSteps.add(new SetupFileSystemStep(true));
    processingSteps.add(new ExtractApkStep(ConfigHandler.getInstance().getBooleanConfigValue(ConfigKeys.ANALYSIS_EXTRACT_APK)));
    processingSteps.add(new DecompileApkStep(ConfigHandler.getInstance().getBooleanConfigValue(ConfigKeys.ANALYSIS_DECOMPILE_APK)));
    processingSteps.add(new ParseSmaliStep(true));

    return processingSteps;
  }

  private static List<Step> buildAnalysisSteps() {
    List<Step> analysisSteps = new ArrayList<>();
    analysisSteps.add(new HeuristicSearchStep(ConfigHandler.getInstance().getBooleanConfigValue(ConfigKeys.ANALYSIS_DO_HEURISTIC)));
    analysisSteps.add(new URLScanStep(ConfigHandler.getInstance().getBooleanConfigValue(ConfigKeys.ANALYSIS_DO_URLSCAN)));
    analysisSteps.add(new NativeCodeStep(true));
    analysisSteps.add(new PermissionCheckStep(ConfigHandler.getInstance().getBooleanConfigValue(ConfigKeys.ANALYSIS_MATCH_APICALLS)));
    analysisSteps.add(new SlicingStep(ConfigHandler.getInstance().getBooleanConfigValue(ConfigKeys.ANALYSIS_DO_SLICING)));
    analysisSteps.add(new SlicingGraphStep(ConfigHandler.getInstance().getBooleanConfigValue(ConfigKeys.ANALYSIS_SLICEGRAPH_CREATE)));
    analysisSteps.add(new SlicingConstTraceStep(ConfigHandler.getInstance().getBooleanConfigValue(ConfigKeys.ANALYSIS_TRACE_SLICINGCONST)));
    analysisSteps.add(new PathLoggerStep(ConfigHandler.getInstance().getBooleanConfigValue(ConfigKeys.ANALYSIS_DO_SAVE_SLICE_PATHS)));
    analysisSteps.add(new SliceAnalysisStep(ConfigHandler.getInstance().getBooleanConfigValue(ConfigKeys.ANALYSIS_DO_SLICEANALYSIS)));

    return analysisSteps;
  }

  private static List<Step> buildCleanupSteps() {
    List<Step> cleanupSteps = new ArrayList<>();
    cleanupSteps.add(new DeleteFilesStep(!ConfigHandler.getInstance().getBooleanConfigValue(ConfigKeys.ANALYSIS_KEEP_FILES)));

    return cleanupSteps;
  }

  public void performAnalysis() throws AnalysisException {
    LOGGER.debug("Preparing analysis of application " + app.getApplicationName());

    try {
      boolean stepsSkipped = false;
      for (Step step : PREPROCESSING_STEPS) {
        // Abort all subsequent steps, if one does not return sucessfully (= true)
        if (!step.process(this)) {
          stepsSkipped = true;
          break;
        }
      }

      // Check if preprocessing did not result in skipping the .apk
      if (stepsSkipped) {
        LOGGER.info("Further analysis steps for " + app.getApplicationName() + " are skipped.");
      } else {
        for (Step step : ANALYSIS_STEPS) {
          if (!step.process(this))
            break;
        }
      }

    } catch (AnalysisException | NullPointerException | NoSuchElementException | ArrayIndexOutOfBoundsException e) {
      handleCaughtException(e);
    } finally {
      LOGGER.info("Slicing results: " + getSliceConstants().size());
      LOGGER.info("Heuristic results: " + getHeuristicResults().size());
      report.writeReport(app.getApplicationName());

      for (Step step : CLEANUP_STEPS) {
        if (!step.process(this))
          break;
      }
    }

    LOGGER.info("Analysis for application " + app.getApplicationName() + " completed");
  }

  private void handleCaughtException(Exception e) {
    LOGGER.error("Analysis for " + app.getApplicationName() + " failed!", e);
    this.addCriticalException(e);
  }

  public Application getApp() {
    return app;
  }

  public List<AnalysisException> getCriticalExceptions() {
    return criticalExceptions;
  }

  public void addCriticalException(Exception e) {
    criticalExceptions.add(new AnalysisException(e.getMessage(), e));
  }

  public List<AnalysisException> getNonCriticalExceptions() {
    return nonCriticalExceptions;
  }

  public void addNonCriticalException(Exception e) {
    nonCriticalExceptions.add(new AnalysisException(e.getMessage(), e));
  }

  public Table<SlicingPattern, Integer, Set<Constant>> getSliceConstants() {
    return sliceConstants;
  }

  public void setSliceConstants(Table<SlicingPattern, Integer, Set<Constant>> sliceConstants) { this.sliceConstants = sliceConstants; }

  public Table<SlicingPattern, Integer, SliceTree> getSliceTrees() { return sliceTrees; }

  public void setSliceTrees(Table<SlicingPattern, Integer, SliceTree> sliceTrees) {
    this.sliceTrees = sliceTrees;
  }

  public List<HResult> getHeuristicResults() {
    return heuristicResults;
  }

  public void setHeuristicResults(List<HResult> heuristicResults) {
    this.heuristicResults = heuristicResults;
  }

  public AnalysisReport getReport() { return report; }
}
