package at.tugraz.iaik.cryptoslice.analysis.heuristic;

import at.tugraz.iaik.cryptoslice.application.CodeLine;
import at.tugraz.iaik.cryptoslice.application.methods.Method;

// This object contains all information for one found Heuristic pattern.
public class HResult {
  private final HPattern pattern;

  private CodeLine cl = null;
  private final Method method;

  public HResult(HPattern pattern, CodeLine cl) {
    this.pattern = pattern;
    this.cl = cl;
    this.method = cl.getMethod();
  }

  public HResult(HPattern pattern, Method method) {
    this.pattern = pattern;
    this.method = method;
  }
}
