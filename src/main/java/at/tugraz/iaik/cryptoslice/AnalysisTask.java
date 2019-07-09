package at.tugraz.iaik.cryptoslice;

import at.tugraz.iaik.cryptoslice.analysis.Analysis;
import at.tugraz.iaik.cryptoslice.analysis.AnalysisException;
import at.tugraz.iaik.cryptoslice.application.Application;

import java.io.File;

public class AnalysisTask implements Runnable {
  private final Analysis analysis;
  private boolean hasNonCriticalExceptions = false;
  private boolean hasCriticalExceptions = false;
  private Throwable criticalException = null;

  public AnalysisTask(File apk) throws AnalysisException {
    analysis = new Analysis(new Application(apk));
  }

  @Override
  public void run() {
    Throwable e = null;

    // Only the first exception is actually captured in order to evade too much rumour.
    try {
      analysis.performAnalysis();

      if (!analysis.getNonCriticalExceptions().isEmpty())
        hasNonCriticalExceptions = true;
      if (!analysis.getCriticalExceptions().isEmpty())
        hasCriticalExceptions = true;

    } catch (AnalysisException | OutOfMemoryError e1) {
      e = e1;
    } finally {
      if (e != null) {
        hasCriticalExceptions = true;
        criticalException = e;
      }
    }
  }

  public boolean hasNonCriticalExceptions() {
    return hasNonCriticalExceptions;
  }

  public boolean hasCriticalException() {
    return hasCriticalExceptions;
  }

  public Throwable getCriticalException() {
    return criticalException;
  }

  public Analysis getAnalysis() {
    return analysis;
  }
}
