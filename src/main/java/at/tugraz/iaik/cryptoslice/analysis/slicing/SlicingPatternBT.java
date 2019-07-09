package at.tugraz.iaik.cryptoslice.analysis.slicing;

import at.tugraz.iaik.cryptoslice.application.CodeLine;

import java.util.Objects;

// Backtracking pattern
public class SlicingPatternBT extends SlicingPattern {
  private final String qualifiedClassName;
  private final String methodName;
  private final String parameterTypes;
  private final int parameterOfInterest;
  private final CodeLine codeLine;
  private byte[][] classAndMethod = null;
  private final String trackReturnValue;

  public SlicingPatternBT(String qualifiedClass, String methodName, String paramSpec, int paramOfInterest, String description) {
    this(qualifiedClass, methodName, paramSpec, paramOfInterest, description, null);
  }

  // Don't search for INVOKE statements - only search the method track back the return value (defined in trackReturnValue)
  public SlicingPatternBT(String qualifiedClass, String methodName, String paramSpec, int paramOfInterest, String description, String trackReturnValue) {
    super(SLICING_TYPE.BACKWARD, description);

    this.qualifiedClassName = qualifiedClass;
    this.methodName = methodName;
    this.parameterTypes = paramSpec;
    this.parameterOfInterest = paramOfInterest;
    this.codeLine = null;
    this.trackReturnValue = trackReturnValue;
  }

  // Constructor for a specific codeline
  public SlicingPatternBT(CodeLine codeLine, int paramOfInterest) {
    super(SLICING_TYPE.BACKWARD, "");

    this.qualifiedClassName = new String(codeLine.getInstruction().getCalledClassAndMethodWithParameter()[0]);
    this.methodName = new String(codeLine.getInstruction().getCalledClassAndMethodWithParameter()[1]);
    this.parameterTypes = new String(codeLine.getInstruction().getCalledClassAndMethodWithParameter()[2]);
    this.parameterOfInterest = paramOfInterest;
    this.codeLine = codeLine;
    this.trackReturnValue = null;
  }

  public String getQualifiedClassName() {
    return qualifiedClassName;
  }

  public String getMethodName() {
    return methodName;
  }

  public byte[] getParameterTypes() {
    // Consider * or "null" in the parameter list (method signature) as wildcard -> null
    if (parameterTypes == null || parameterTypes.equals("*") || parameterTypes.equals("null")) {
      return null;
    }

    return parameterTypes.getBytes();
  }

  public int getParameterOfInterest() {
    return parameterOfInterest;
  }

  public CodeLine getCodeLine() {
    return codeLine;
  }

  public String getTrackReturnValue() {
    return trackReturnValue;
  }

  public byte[][] getClassAndMethod() {
    return classAndMethod;
  }

  public void setClassAndMethod(byte[][] classAndMethod) {
    this.classAndMethod = classAndMethod;
  }

  public byte[][] getCmp() {
    return new byte[][] { qualifiedClassName.getBytes(), methodName.getBytes(), getParameterTypes() };
  }

  @Override
  public int hashCode() {
    return Objects.hash(qualifiedClassName, methodName, parameterTypes, parameterOfInterest);
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj)
      return true;

    if (obj == null || getClass() != obj.getClass())
      return false;

    final SlicingPatternBT other = (SlicingPatternBT) obj;

    return Objects.equals(this.qualifiedClassName, other.qualifiedClassName) &&
        Objects.equals(this.methodName, other.methodName) &&
        Objects.equals(this.parameterTypes, other.parameterTypes) &&
        Objects.equals(this.parameterOfInterest, other.parameterOfInterest);
  }

  @Override
  public String toString() {
    return "Backtracking pattern: " + getDescription() + "\nclass=" + qualifiedClassName +
        ", method=" + methodName + ", parameterTypes=" + parameterTypes +
        ", parameterOfInterest=" + parameterOfInterest;
  }
}
