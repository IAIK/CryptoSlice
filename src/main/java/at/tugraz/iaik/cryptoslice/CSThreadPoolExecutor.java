package at.tugraz.iaik.cryptoslice;

import at.tugraz.iaik.cryptoslice.analysis.AnalysisException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.util.Collection;
import java.util.concurrent.*;

public class CSThreadPoolExecutor extends ThreadPoolExecutor {
  private static final Logger LOGGER = LoggerFactory.getLogger(CSThreadPoolExecutor.class);
  private boolean gotUncaughtException = false;
  private int criticalExceptionCount = 0;
  private int uncriticalExceptionCount = 0;
  private int analysisCount = 0;
  private final int apkCount;
  private int skipped = 0;

  public CSThreadPoolExecutor(Collection<File> apks, int corePoolSize, int maximumPoolSize, long keepAliveTime, TimeUnit unit) {
    super(corePoolSize, maximumPoolSize, keepAliveTime, unit, new ArrayBlockingQueue<Runnable>(apks.size()));

    apkCount = apks.size();
    for (File apk : apks) {
      try {
        AnalysisTask aft = new AnalysisTask(apk);
        this.submit(aft, aft);
      } catch (AnalysisException e) {
        LOGGER.error("Could not generate Analysis object, skipping file: " + apk, e);
        skipped++;
      }
    }
  }

  @Override
  protected synchronized void beforeExecute(Thread t, Runnable r) {
    analysisCount++;
    LOGGER.info("Beginning analysis " + analysisCount + " of " + apkCount);
    super.beforeExecute(t, r);
  }

  @Override
  protected void afterExecute(Runnable r, Throwable t) {
    super.afterExecute(r, t);

    if (t != null) {
      LOGGER.error("afterExecute() found a throwable.", t);
      gotUncaughtException = true;
    } else if (r instanceof FutureTask<?>) {
      try {
        @SuppressWarnings("unchecked")
        AnalysisTask at = ((FutureTask<AnalysisTask>) r).get();
        if (at.hasNonCriticalExceptions())
          uncriticalExceptionCount++;

        if (at.hasCriticalException()) {
          criticalExceptionCount++;
          LOGGER.error("Analysis of '" + at.getAnalysis().getApp().getApplicationName() + "' failed!\n\n", at.getCriticalException());
        }

      } catch (CancellationException e) {
        LOGGER.warn("Analysis skipped!");
        skipped++;
      } catch (InterruptedException e) {
        LOGGER.warn("Analysis interrupted!");
        skipped++;
      } catch (ExecutionException e) {
        // This is thrown by FutureTask.get() if the task threw an exception.
        gotUncaughtException = true;
        LOGGER.error("Analysis failed with exception!", e);
      }
    }

    if (gotUncaughtException) {
      LOGGER.error("Something unexpected happened.");
    }
  }

  public synchronized void printStats() {
    String stats = "\n\nAnalysis Results:";
    stats += "\n- Inspected APKs: " + apkCount;
    stats += "\n- Analyses: " + analysisCount;
    if (skipped > 0) {
      stats += "\nSkipped APKs due to errors: " + skipped;
    }
    stats += "\n- Uncritical exceptions: " + uncriticalExceptionCount;
    stats += "\n- Critical exceptions: " + criticalExceptionCount;

    LOGGER.info(stats);
  }
}
