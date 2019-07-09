package at.tugraz.iaik.cryptoslice.analysis;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public abstract class Step {
  protected Logger LOGGER = LoggerFactory.getLogger(getClass());
  protected String name = "Abstract Step";
  protected boolean enabled;

  public final boolean process(Analysis analysis) throws AnalysisException {
    boolean success = true;

    if (this.enabled) {
      if (doBefore(analysis)) {
        success = doProcessing(analysis);
        doAfter(analysis);
      }
    }

    return success;
  }

  /**
   * This is where the main activity happens.
   *
   * @return true if the processing of further steps should proceed
   */
  protected abstract boolean doProcessing(Analysis analysis) throws AnalysisException;

  /**
   * A hook that can be implemented by subclasses to do things before main processing.
   *
   * @param analysis
   * @return true if the doProcessing method should be processed
   */
  protected boolean doBefore(Analysis analysis) throws AnalysisException {
    LOGGER.debug("Start Analysis Step: " + this.name);

    return true;
  }

  /**
   * A hook that can be implemented by subclasses to do things before main processing.
   *
   * @param analysis
   * @return if the processing of further steps should proceed
   */
  protected boolean doAfter(Analysis analysis) throws AnalysisException {
    LOGGER.debug("Stop Analysis Step: " + this.name);

    return true;
  }
}
