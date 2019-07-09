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

import java.util.LinkedList;

public class TryCatchBlock {
  // The line numbers of begin and end of the code of this try-block
  private int begin, end;

  /**
   * The truly last line of this tryBlock.
   * Meaning the last catch, which is always the end of a BasicBlock.
   */
  private CodeLine blockEnd = null;

  /**
   * The first lines of all corresponding catches.
   */
  private LinkedList<CodeLine> catches = null;

  public TryCatchBlock(int begin, int end) {
    this.begin = begin;
    this.end = end;
  }

  public TryCatchBlock(int begin, int end, CodeLine blockEnd) {
    this.begin = begin;
    this.end = end;
    this.blockEnd = blockEnd;
  }

  public TryCatchBlock(int begin, int end, LinkedList<CodeLine> catches) {
    this.begin = begin;
    this.end = end;
    this.catches = catches;
  }

  public TryCatchBlock(int begin, int end, CodeLine blockEnd, LinkedList<CodeLine> catches) {
    this.begin = begin;
    this.end = end;
    this.blockEnd = blockEnd;
    this.catches = catches;
  }

  // probably not all those sets necessary
  public int getBegin() {
    return begin;
  }

  public void setBegin(int begin) {
    this.begin = begin;
  }

  public int getEnd() {
    return end;
  }

  public void setEnd(int end) {
    this.end = end;
  }

  public CodeLine getBlockEnd() {
    return blockEnd;
  }

  public void setBlockEnd(CodeLine blockEnd) {
    this.blockEnd = blockEnd;
  }

  public LinkedList<CodeLine> getCatches() {
    return catches;
  }

  public void setCatches(LinkedList<CodeLine> catches) {
    this.catches = catches;
  }

  public void addCatch(CodeLine newCatch) {
    if (catches == null)
      catches = new LinkedList<CodeLine>();

    catches.add(newCatch);
  }
}
