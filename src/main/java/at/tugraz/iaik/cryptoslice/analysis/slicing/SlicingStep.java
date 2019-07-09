package at.tugraz.iaik.cryptoslice.analysis.slicing;

import at.tugraz.iaik.cryptoslice.analysis.Analysis;
import at.tugraz.iaik.cryptoslice.analysis.AnalysisException;
import at.tugraz.iaik.cryptoslice.analysis.Step;
import at.tugraz.iaik.cryptoslice.application.Application;
import at.tugraz.iaik.cryptoslice.application.CodeLine;
import at.tugraz.iaik.cryptoslice.application.DetectionLogicError;
import at.tugraz.iaik.cryptoslice.application.instructions.Constant;
import at.tugraz.iaik.cryptoslice.utils.xml.XMLTPatternSource;
import com.google.common.collect.HashBasedTable;
import com.google.common.collect.Table;

import java.util.*;

// Triggers a backtracking search for parameters of interesting methods
public class SlicingStep extends Step {
  private final Set<SlicingPattern> patterns;
  private Analysis analysis;
  private Table<SlicingPattern, Integer, Set<Constant>> sliceConstants;
  private Table<SlicingPattern, Integer, SliceTree> sliceTrees;
  private boolean exceptionWhileTracking = false;

  public SlicingStep(boolean enabled) {
    this.name = "Slicing";
    this.patterns = XMLTPatternSource.getInstance().getPatterns();
    this.enabled = enabled;
  }

  @Override
  public boolean doProcessing(Analysis analysis) throws AnalysisException {
    this.analysis = analysis;
    Application app = analysis.getApp();
    this.sliceConstants = HashBasedTable.create();
    this.sliceTrees = HashBasedTable.create();
    this.exceptionWhileTracking = false;

    if (patterns.isEmpty()) {
      LOGGER.warn("No slicing patterns to analyze.");
      return true;
    }

    LOGGER.debug("Analyzing " + app.getApplicationName() + " using " + patterns.size() + " slicing-patterns.");

    List<CodeLine> searchIds = new ArrayList<>();

    try {
      for (SlicingPattern pattern : patterns) {
        if (pattern.isEnabled()) {
          // BACKWARD
          if (pattern.getSlicingType() == SlicingPattern.SLICING_TYPE.BACKWARD) {
            SlicingPatternBT patternBT = (SlicingPatternBT) pattern;
            LOGGER.debug("\n\nTracking backward {}:{}({}), parameterOfInterest: {}", patternBT.getQualifiedClassName(),
                patternBT.getMethodName(),
                (patternBT.getParameterTypes() != null ? new String(patternBT.getParameterTypes()) : ""),
                patternBT.getParameterOfInterest());

            SlicerBackward slicer = new SlicerBackward(app, searchIds);
            SlicingCriterion criterion = new SlicingCriterion(patternBT);
            slicer.startSearch(criterion);
            postTracking(criterion);
          } else { // FORWARD
            SlicingPatternFT patternFT = (SlicingPatternFT) pattern;

            if (patternFT.getType().equals("OBJECT")) {
              LOGGER.debug("\n\nTracking forward " + patternFT.getQualifiedClassName() + "->" + patternFT.getMethodName());

              SlicerForward slicer = new SlicerForward(app, searchIds);
              SlicingCriterion criterion = new SlicingCriterion(patternFT);
              slicer.startSearch(criterion);
              postTracking(criterion);
            } else { // XPATH_QUERY, RESOURCE_ID
              LOGGER.debug("\n\nTracking forward " + patternFT.getType() + ":" + patternFT.getSearchPattern());

              Set<String> resourceIds = new HashSet<>();
              if (patternFT.getType().equals("XPATH_QUERY")) {
                resourceIds.addAll(ResourceUtils.findResourceIdsForInputType(patternFT.getSearchPattern(), app));
              } else if (patternFT.getType().equals("RESOURCE_ID")) {
                resourceIds.add(patternFT.getSearchPattern());
              }

              Map<String, String> constantIds = ResourceUtils.findConstForResourceIds(resourceIds, app);
              // Create a new SlicePattern and SlicingCriterion for every resourceId.
              for (Map.Entry<String, String> constant : constantIds.entrySet()) {
                SlicingPatternFT p = new SlicingPatternFT(constant.getKey(), "RESOURCE_ID", patternFT.getDescription());
                p.setEnabled(true);
                p.setConstantId(constant.getValue());

                SlicerForward slicer = new SlicerForward(app, searchIds);
                SlicingCriterion criterion = new SlicingCriterion(p);
                slicer.startSearch(criterion);
                postTracking(criterion);
              }
            }
          }
        }
      }

      LOGGER.info("Finished Slicing step for application " + app.getApplicationName() +
          (exceptionWhileTracking ? "[Finished with Exceptions]" : ""));
      analysis.setSliceConstants(sliceConstants);
      analysis.setSliceTrees(sliceTrees);
    } catch (DetectionLogicError e) {
      throw new AnalysisException(e);
    }

    return true;
  }

  private void postTracking(SlicingCriterion criterion) {
    // Add the found constants and trees for the current pattern, in case the search delivered results
    if (!criterion.getSliceConstants().isEmpty()) {
      for (Integer searchId : criterion.getSliceConstants().keySet()) {
        sliceConstants.put(criterion.getPattern(), searchId, (Set<Constant>) criterion.getSliceConstants().get(searchId));

        Set<Constant> constants = (Set<Constant>) criterion.getSliceConstants().get(searchId);
        for (Constant c : constants)
          LOGGER.info("Adding const:\n" + c);
      }
    }

    if (!criterion.getSliceTrees().isEmpty()) {
      for (Map.Entry<Integer, SliceTree> tree : criterion.getSliceTrees().entrySet())
        sliceTrees.put(criterion.getPattern(), tree.getKey(), tree.getValue());
    }

    if (!criterion.getExceptionList().isEmpty()) {
      exceptionWhileTracking = true;

      for (Throwable thr : criterion.getExceptionList())
        analysis.addNonCriticalException(new AnalysisException(thr.getMessage(), thr));
    }
  }
}
