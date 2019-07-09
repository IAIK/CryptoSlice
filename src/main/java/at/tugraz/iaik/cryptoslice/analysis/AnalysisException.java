package at.tugraz.iaik.cryptoslice.analysis;

public class AnalysisException extends Exception {
  private static final long serialVersionUID = -9107445111161739094L;

  public AnalysisException(String message, Throwable cause) {
    super(message, cause);
  }

  public AnalysisException(String message) {
    super(message);
  }

  public AnalysisException(Throwable cause) {
    super(cause);
  }
}
