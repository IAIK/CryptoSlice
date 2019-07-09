package at.tugraz.iaik.cryptoslice.analysis.slicing;

// Base class for a pattern that is used for tracking.
public abstract class SlicingPattern {
  public enum SLICING_TYPE {
    BACKWARD, FORWARD
  }

  private final SLICING_TYPE slicingType;
  private final String description;
  private boolean enabled;

  protected SlicingPattern(SLICING_TYPE type, String description) {
    this.slicingType = type;
    this.description = description;
  }

  public SLICING_TYPE getSlicingType() { return this.slicingType; }

  public String getDescription() { return this.description; }

  public boolean isEnabled() {
    return this.enabled;
  }

  public void setEnabled(boolean enabled) {
    this.enabled = enabled;
  }
}
