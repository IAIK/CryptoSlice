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

public class Target {
  private final CodeLine to;

  public Target(CodeLine to) {
    this.to = to;
  }

  public CodeLine getTo() {
    return to;
  }

  @Override
  public int hashCode() {
    return Objects.hash(to);
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj)
      return true;

    if (obj == null || getClass() != obj.getClass())
      return false;

    final Target other = (Target) obj;

    return Objects.equals(this.to, other.to);
  }
}
