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
import at.tugraz.iaik.cryptoslice.application.SyntaxException;

import java.util.LinkedList;
import java.util.Objects;

public class BasicBlock {

  public static class FoundCodeLine {
    private final CodeLine cl;
    private final int index;
    private final BasicBlock bb;

    public FoundCodeLine(CodeLine cl, BasicBlock bb, int index) {
      this.cl = cl;
      this.index = index;
      this.bb = bb;
    }

    public CodeLine getCodeLine() {
      return cl;
    }

    public int getIndex() {
      return index;
    }

    public BasicBlock getBasicBlock() {
      return bb;
    }
  }

  private final LinkedList<CodeLine> codeLines;
  private final Method method;

  private final LinkedList<BasicBlock> previousBlocks = new LinkedList<>();
  private final LinkedList<BasicBlock> nextBlocks = new LinkedList<>();

  private final LinkedList<Link> previousLinkBlocks = new LinkedList<>();
  private final LinkedList<Link> nextLinkBlocks = new LinkedList<>();

  private boolean hasReturn = false;
  private boolean hasThrow = false;
  private boolean hasGoto = false;
  private boolean hasDeadCode = false;
  private boolean isTryBlock = false;
  private boolean isCatchBlock = false;

  // The label assigned by a DFS
  private int label = -1;

  /**
   * A BasicBlock.
   *
   * @param codeLines for this BB
   * @param method the method where this BB belongs to
   */
  public BasicBlock(LinkedList<CodeLine> codeLines, Method method) {
    this.codeLines = codeLines;
    this.method = method;
  }

  /**
   * Get the previous CodeLine which contains actual code (is not empty, a comment etc).
   *
   * @param bb the BB in which to search
   * @param index the current index, not previous CodeLine index
   * @return the corresponding CodeLine or a SyntaxException
   * @throws SyntaxException if no real instruction can be found in the given BB
   */
  public static BasicBlock.FoundCodeLine getPreviousCodeLine(BasicBlock bb, int index) throws SyntaxException {
    while (index > 0) {
      CodeLine cl = bb.getCodeLines().get(--index);
      if (cl.isCode())
        return new FoundCodeLine(cl, bb, index);
    }

    throw new SyntaxException("Could not find previous 'real' instruction in given BB!");
  }

  /**
   * Get the previous CodeLine which contains actual code (is not empty, a comment etc).
   *
   * The previous opcode CAN reside in another opcode if, and only if, the searched BB is part of the following
   * try/catch construct and there is only one previous block. That means the BB is not a catch block but the block
   * directly after the try/catch construct.
   *
   * invoke-static {v1, p2}, La/b;->decrypt(String;String;)String;   <- We want to find this, but the BB already ended!
   * :try_end_0
   * .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0 <- BB ends here
   * move-result-object p2                        <- p2 is currently tracked and we need the previous opcode in this BB
   *
   * The BB where the previous cl real opcode was found is saved in the returned FoundCodeLine.
   * It might be different from the parameter.
   *
   * @param bb the BB in which to search
   * @param cl the codeline from which the search starts, the search will begin before this line
   * @return the corresponding CodeLine or a SyntaxException
   * @throws SyntaxException if no real instruction can be found in the given BB (or the previous one)
   */
  public static BasicBlock.FoundCodeLine getPreviousOpcode(BasicBlock bb, CodeLine cl) throws SyntaxException {
    int index = bb.getCodeLines().indexOf(cl);

    while (index > 0) {
      cl = bb.getCodeLines().get(--index);
      if (cl.isCode())
        return new FoundCodeLine(cl, bb, index);
    }

    /*
     * If we are searching for an invoke because we have a RETURN opcode, the corresponding invoke can be in
     * another BB if we are right beneath a try/catch BB and not the catch block itself.
     */
    if (!bb.isCatchBlock() && bb.getPreviousBB().size() == 1)
      return BasicBlock.getLastCodeLine(bb.getPreviousBB().getFirst());

    // If we can not find something we have to abort!
    throw new SyntaxException("Could not find previous 'real' instruction in given BB!");
  }

  public static BasicBlock.FoundCodeLine getNextCodeLine(BasicBlock bb, int index) throws SyntaxException {
    while (index < bb.getCodeLines().size()-1) {
      CodeLine cl = bb.getCodeLines().get(++index);
      if (cl.isCode())
        return new FoundCodeLine(cl, bb, index);
    }

    throw new SyntaxException("Could not find next 'real' instruction in given BB!");
  }

  public static BasicBlock.FoundCodeLine getNextOpcode(BasicBlock bb, CodeLine cl) throws SyntaxException {
    int index = bb.getCodeLines().indexOf(cl);

    while (index < bb.getCodeLines().size()-1) {
      cl = bb.getCodeLines().get(++index);
      if (cl.isCode())
        return new FoundCodeLine(cl, bb, index);
    }

    if (!bb.getNextBB().isEmpty()) {
      return BasicBlock.getFirstCodeLine(bb.getNextBB().getFirst());
    }

    // If we can not find something we have to abort!
    throw new SyntaxException("Could not find next 'real' instruction in given BB!");
  }

  /**
   * Returns the last codeline which contains a real opcode (not comment, dot prefix etc) from the BB.
   *
   * @param bb the BasicBlock to search
   * @return the found line
   * @throws SyntaxException if now line was found
   */
  public static BasicBlock.FoundCodeLine getLastCodeLine(BasicBlock bb) throws SyntaxException {
    return BasicBlock.getPreviousCodeLine(bb, bb.getCodeLines().size());
  }

  public static BasicBlock.FoundCodeLine getFirstCodeLine(BasicBlock bb) throws SyntaxException {
    return BasicBlock.getNextCodeLine(bb, -1);
  }

  public String getUniqueId() {
    //return getMethod().getSmaliClass().getFullClassName(true) + '(' + getMethod().getName() + ')';
    return getMethod().getSmaliClass().getFullClassName(true) + '(' + getMethod().getName() + ')' + ',' + label;
    //return getMethod().getSmaliClass().getUniqueId() + ',' + getMethod().getLabel() + ',' + label;
  }

  public LinkedList<CodeLine> getCodeLines() {
    return codeLines;
  }

  public Method getMethod() {
    return method;
  }

  public LinkedList<BasicBlock> getPreviousBB() {
    return previousBlocks;
  }

  /**
   * This method adds a BB to the list of previous BBs.
   *
   * @param bb the bb to add to the list of previous BBs
   */
  public void addPreviousBB(BasicBlock bb) {
    if (!previousBlocks.contains(bb))
      previousBlocks.add(bb);
  }

  public LinkedList<BasicBlock> getNextBB() {
    return nextBlocks;
  }

  /**
   * This method adds a BB to the list of following BBs.
   *
   * @param bb the bb to add to the list of BBs following this BB
   */
  public void addNextBB(BasicBlock bb) {
    // multiple following BBs are possible (case, if-else, exceptions, ...)
    if (!(nextBlocks.contains(bb)))
      nextBlocks.add(bb);
  }

  public LinkedList<Link> getPreviousLinkBlocks() {
    return previousLinkBlocks;
  }

  public void addPreviousLinkBlocks(Link link) {
    if (!previousLinkBlocks.contains(link))
      previousLinkBlocks.add(link);
  }

  public LinkedList<Link> getNextLinkBlocks() {
    return nextLinkBlocks;
  }

  public void addNextLinkBlocks(Link link) {
    if (!nextLinkBlocks.contains(link))
      nextLinkBlocks.add(link);
  }

  public boolean hasReturn(){
    return hasReturn;
  }

  public void setHasReturn(boolean hasReturn){
    this.hasReturn = hasReturn;
  }

  public boolean hasThrow(){
    return hasThrow;
  }

  public void setHasThrow(boolean hasThrow) {
    this.hasThrow = hasThrow;
  }

  public boolean hasGoto(){
    return hasGoto;
  }

  public void setHasGoto(boolean hasGoto) {
    this.hasGoto = hasGoto;
  }

  /**
   * Checks whether the BB contains dead code. This most likely results when someone
   * patches a program in order to return something and skip real code. BBs are build
   * after jmp/goto label/targets and this should not occur in "normal" apps.
   *
   * @return true if the BB contains a return opcode which is not the last opcode.
   */
  public boolean hasDeadCode() {
    return hasDeadCode;
  }

  public void setHasDeadCode(boolean hasDeadCode){
    this.hasDeadCode = hasDeadCode;
  }

  public boolean isTryBlock(){
    return isTryBlock;
  }

  public void setIsTryBlock(boolean isTryBlock) {
    this.isTryBlock = isTryBlock;
  }

  public boolean isCatchBlock() {
    return isCatchBlock;
  }

  public void setIsCatchBlock(boolean isCatchBlock) {
    this.isCatchBlock = isCatchBlock;
  }

  /**
   * Get the unique label of this BB within a Method.
   *
   * @return the label of this BB
   */
  public int getLabel() {
    return label;
  }

  /**
   * Set the unique label of this BB within a Method.
   *
   * @param label the label of this BB
   */
  public void setLabel(int label) {
    this.label = label;
  }

  @Override
  public String toString(){
    StringBuilder bb = new StringBuilder();
    for (CodeLine cl: this.getCodeLines()) {
      bb.append(cl.getNrAndLine());
      bb.append("\n");
    }

    return bb.toString();
  }

  @Override
  public int hashCode() {
    return Objects.hash(codeLines);
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj)
      return true;

    if (obj == null || getClass() != obj.getClass())
      return false;

    final BasicBlock other = (BasicBlock) obj;

    return Objects.equals(this.codeLines, other.codeLines);
  }
}
