/* SAAF: A static analyzer for APK files.
 * Copyright (C) 2013  syssec.rub.de
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
package at.tugraz.iaik.cryptoslice.application.methods;

import at.tugraz.iaik.cryptoslice.application.CodeLine;

import java.util.Objects;

public class Link {
  private final CodeLine from;
  private final CodeLine to;
  private String label = null;

  public Link(CodeLine from, CodeLine to) {
    this.from = from;
    this.to = to;
  }

  public Link(CodeLine from, CodeLine to, String label) {
    this.from = from;
    this.to = to;
    this.label = label;
  }

  @Override
  public int hashCode() {
    return Objects.hash(from, to);
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj)
      return true;

    if (obj == null || getClass() != obj.getClass())
      return false;

    final Link other = (Link) obj;

    return Objects.equals(this.from, other.from) &&
        Objects.equals(this.to, other.to);
  }

  public CodeLine getFrom() {
    return from;
  }

  public CodeLine getTo() {
    return to;
  }

  public String getLabel() {
    return label;
  }
}