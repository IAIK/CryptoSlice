package at.tugraz.iaik.cryptoslice.analysis.heuristic;

import com.google.common.collect.ComparisonChain;

import java.util.Objects;

// This object contains all information for a pattern used by the heuristic logic.
public class HPattern implements Comparable<HPattern> {
  private final String pattern;
  private final String type;
  private final String description;
  private boolean enabled = true;

  public HPattern(String pattern, String type, String description) {
    this.pattern = pattern;
    this.type = type;
    this.description = description;
  }

  public String getPattern() {
    return pattern;
  }

  public String getType() {
    return type;
  }

  public boolean isEnabled() {
    return this.enabled;
  }

  public void setEnabled(boolean enabled) {
    this.enabled = enabled;
  }

  @Override
  public int compareTo(HPattern other) {
    return ComparisonChain.start()
        .compare(this.pattern, other.pattern)
        .compare(this.type, other.type)
        .result();
  }

  @Override
  public int hashCode() {
    return Objects.hash(pattern, type, description);
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj)
      return true;

    if (obj == null || getClass() != obj.getClass())
      return false;

    final HPattern other = (HPattern) obj;

    return Objects.equals(this.pattern, other.pattern) &&
        Objects.equals(this.type, other.type) &&
        Objects.equals(this.description, other.description);
  }

  @Override
  public String toString() {
    return "HPattern [" +
        "pattern=" + pattern + ", " +
        "type=" + type + ", " +
        "description=" + description + "]";
  }
}
