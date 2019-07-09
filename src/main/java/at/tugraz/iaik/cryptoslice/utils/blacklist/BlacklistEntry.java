package at.tugraz.iaik.cryptoslice.utils.blacklist;

import java.util.Objects;

public class BlacklistEntry implements Comparable<BlacklistEntry>{
  private String path;

  public BlacklistEntry(String value) {
    this.path = value;
  }

  public String getPath() {
    return path;
  }

  public void setPath(String path) {
    this.path = path;
  }

  @Override
  public int compareTo(BlacklistEntry o) {
    return path.compareTo(o.path);
  }

  @Override
  public int hashCode() {
    return Objects.hash(path);
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj) {
      return true;
    }
    if (obj == null || getClass() != obj.getClass()) {
      return false;
    }

    final BlacklistEntry other = (BlacklistEntry) obj;
    return Objects.equals(this.path, other.path);
  }
}