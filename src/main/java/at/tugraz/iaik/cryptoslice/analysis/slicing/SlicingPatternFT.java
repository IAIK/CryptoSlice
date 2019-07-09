package at.tugraz.iaik.cryptoslice.analysis.slicing;

import java.util.Objects;

// Forwardtracking pattern
public class SlicingPatternFT extends SlicingPattern {
  private final String searchPattern;
  private final String qualifiedClassName;
  private final String methodName;
  private final String type;
  private String constantId = "";

  // Constructor for the types XPATH_QUERY and RESOURCE_ID
  public SlicingPatternFT(String searchPattern, String type, String description) {
    super(SLICING_TYPE.FORWARD, description);

    this.searchPattern = searchPattern;
    this.qualifiedClassName = null;
    this.methodName = null;
    this.type = type;
  }

  // Constructor for the type OBJECT
  public SlicingPatternFT(String qualifiedClass, String methodName, String type, String description) {
    super(SLICING_TYPE.FORWARD, description);

    this.searchPattern = null;
    this.qualifiedClassName = qualifiedClass;
    this.methodName = methodName;
    this.type = type;
  }

  public String getDescription() { return super.getDescription(); }

  public String getSearchPattern() {
    return searchPattern;
  }

  public String getQualifiedClassName() {
    return qualifiedClassName;
  }

  public String getMethodName() {
    return methodName;
  }

  public String getType() {
    return type;
  }

  public String getConstantId() {
    return constantId;
  }

  public void setConstantId(String constantId) {
    this.constantId = constantId;
  }

  @Override
  public int hashCode() {
    return Objects.hash(searchPattern, qualifiedClassName, methodName, type);
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj)
      return true;

    if (obj == null || getClass() != obj.getClass())
      return false;

    final SlicingPatternFT other = (SlicingPatternFT) obj;

    return Objects.equals(this.searchPattern, other.searchPattern) &&
        Objects.equals(this.qualifiedClassName, other.qualifiedClassName) &&
        Objects.equals(this.methodName, other.methodName) &&
        Objects.equals(this.type, other.type);
  }

  @Override
  public String toString() {
    return "Forwardtracking pattern: " + getDescription() + ", type=" + type + ",\nsearchPattern=" + searchPattern +
        ", constantId=" + constantId + ",\nclass=" + qualifiedClassName + ", method=" + methodName;
  }
}
