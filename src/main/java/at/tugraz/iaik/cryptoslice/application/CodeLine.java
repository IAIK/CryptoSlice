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
package at.tugraz.iaik.cryptoslice.application;

import at.tugraz.iaik.cryptoslice.application.instructions.Instruction;
import at.tugraz.iaik.cryptoslice.application.instructions.InstructionType;
import at.tugraz.iaik.cryptoslice.application.methods.Method;
import at.tugraz.iaik.cryptoslice.utils.ByteUtils;
import com.google.common.collect.ComparisonChain;

import java.util.Arrays;
import java.util.Objects;

public class CodeLine implements Comparable<CodeLine> {
  private final byte[] line;
  private final int lineNr;
  private final SmaliClass sc;
  private final Instruction instruction;
  private StringBuilder clSb = null;

  // A reference to the method where this cl comes from, may be null!
  private Method method = null;

  public CodeLine(byte[] line, int lineNr, SmaliClass sc) {
    this.line = trim(line);
    this.lineNr = lineNr;
    this.sc = sc;
    this.instruction = new Instruction(this);
  }

  public boolean startsWith(byte[] pattern) {
    return ByteUtils.startsWith(line, pattern);
  }

  public boolean contains(byte[] pattern) {
    return ByteUtils.contains(line, pattern);
  }

  public boolean isEmpty() {
    return (line.length == 0);
  }

  public boolean isCode() {
    if (instruction.getType() == InstructionType.NOT_YET_PARSED
        || instruction.getType() == InstructionType.SMALI_DOT_COMMENT
        || instruction.getType() == InstructionType.EMPTY_LINE
        || instruction.getType() == InstructionType.LABEL
        || instruction.getType() == InstructionType.SMALI_HASH_KEY_COMMENT
        || instruction.getType() == InstructionType.UNKNOWN
        || instruction.getType() == InstructionType.NOP)
      return false;
    else
      return true;
  }

  /**
   * Deletes all whitespace and non printable bytes (bytes <= 32)
   * from the beginning and the end of the byte array.
   *
   * @param line
   * @return
   */
  private static byte[] trim(byte[] line) {
    int begin = 0;
    while (begin < line.length && line[begin] <= 32) begin++;

    int end = line.length-1;
    while (end >= 0 && line[end] <= 32) { end--; }

    if (end < begin) return new byte[0];
    else return Arrays.copyOfRange(line, begin, end + 1);
  }

  public SmaliClass getSmaliClass() {
    return sc;
  }

  public byte[] getLine() {
    return line;
  }

  public int getLineNr() {
    return lineNr;
  }

  public String getNrAndLine(){
    return lineNr + " " + new String(line);
  }

  public Instruction getInstruction() {
    return instruction;
  }

  public Method getMethod() {
    return method;
  }

  public void setMethod(Method method) {
    this.method = method;
  }

  @Override
  public int compareTo(CodeLine other) {
    return ComparisonChain.start()
        .compare(this.lineNr, other.lineNr)
        .compare(this.method, other.method)
        .result();
  }

  @Override
  public int hashCode() {
    return Arrays.hashCode(line) + Objects.hash(lineNr, method);
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj)
      return true;

    if (obj == null || getClass() != obj.getClass())
      return false;

    final CodeLine other = (CodeLine) obj;

    return Arrays.equals(this.line, other.line)
        && Objects.equals(this.lineNr, other.lineNr)
        && Objects.equals(this.method, other.method);
  }

  @Override
  public String toString() {
    if (clSb == null) { // init
      clSb = new StringBuilder();
      clSb.append(lineNr);
      clSb.append(": ");
      clSb.append(new String(line));
    }

    return clSb.toString();
  }
}
