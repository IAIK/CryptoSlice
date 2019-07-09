package at.tugraz.iaik.cryptoslice.analysis.slicing;

import at.tugraz.iaik.cryptoslice.application.CodeLine;
import at.tugraz.iaik.cryptoslice.application.SyntaxException;
import at.tugraz.iaik.cryptoslice.application.methods.BasicBlock;
import at.tugraz.iaik.cryptoslice.utils.config.ConfigHandler;
import at.tugraz.iaik.cryptoslice.utils.config.ConfigKeys;
import com.google.common.base.Predicate;
import com.google.common.collect.Iterables;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;

public class TodoList {
  private static final Logger LOGGER = LoggerFactory.getLogger(TodoList.class);

  protected static final int MAX_FUZZY_LEVEL = ConfigHandler.getInstance().getIntConfigValue(ConfigKeys.ANALYSIS_SLICING_MAXFUZZYLEVEL);
  protected static final int MAX_RS_COUNT = ConfigHandler.getInstance().getIntConfigValue(ConfigKeys.ANALYSIS_SLICING_MAXRSCOUNT);

  private final Queue<RegisterSearch> registerQueue = new ArrayDeque<>();
  private final Queue<ClassContentTracker> fieldQueue = new ArrayDeque<>();
  private final Queue<ClassContentTracker> returnValueQueue = new ArrayDeque<>();
  private final Queue<ClassContentTracker> arrayQueue = new ArrayDeque<>();
  private final List<RegisterSearch> registerQueueDone = new ArrayList<>();
  private final List<ClassContentTracker> fieldQueueDone = new ArrayList<>();
  private final List<ClassContentTracker> arrayQueueDone = new ArrayList<>();
  private final List<ClassContentTracker> returnValueQueueDone = new ArrayList<>();

  private final Slicer slicer;

  public TodoList(Slicer slicer) {
    this.slicer = slicer;
  }

  public boolean addRegisterToTrack(RegisterSearch rs) {
    LOGGER.debug(" -> Add REGISTER: {}, {}:{}\tfuzzy={}/{}, bb={}",
        new String(rs.getRegister()), rs.getBB().getMethod().getName(), rs.getIndex(), rs.getFuzzyLevel(),
        rs.getFuzzyOffset(), rs.getBB().getUniqueId());

    if (rs.getFuzzyLevel() + rs.getFuzzyOffset() > MAX_FUZZY_LEVEL) {
      LOGGER.debug("    Maximum fuzzy level reached (" + MAX_FUZZY_LEVEL + "): aborting.");
      return false;
    }

    registerQueue.add(rs);

    return true;
  }

  public RegisterSearch getNextRegisterToTrack() {
    RegisterSearch rs = null;

    while (rs == null && !registerQueue.isEmpty()) {
      rs = registerQueue.remove();

      // linkDuplicateTracks() returns null if the register should not be tracked further.
      rs = linkDuplicateTracks(rs);
    }

    if (rs == null) // in case the regList is empty
      return null;

    registerQueueDone.add(rs);

    if (LOGGER.isDebugEnabled()) {
      CodeLine cl =  rs.getBB().getCodeLines().get(rs.getIndexAbsolute());
      LOGGER.debug("\n\n-> TRACKING REGISTER: {}, {}.{}:{}\tfuzzy={}/{}", new String(rs.getRegister()),
          rs.getBB().getMethod().getSmaliClass().getFullClassName(true), rs.getBB().getMethod().getName(),
          cl.getLineNr(), rs.getFuzzyLevel(), rs.getFuzzyOffset());
    }

    return rs;
  }

  private static boolean checkRsForEquality(RegisterSearch rs1, RegisterSearch rs2) {
    if (!Arrays.equals(rs1.getRegister(), rs2.getRegister())) return false;
    if (rs1.getBB() != rs2.getBB()) return false;
    if (rs1.getIndex() != rs2.getIndex()) return false;

    return true;
  }

  /**
   * Checks if a given RegisterSearch was previously performed and if so, search the Slice graph node that was
   * found first when tracking the previously performed RegisterSearch. The current RegisterSearch is then linked with
   * the afore found node.
   *
   * Note that although the current and previous RegisterSearch objects need to have the same target register, the
   * previous (source) register might be different. I.e. one could call a method like: invoke-virtual {v4, v3} ... and
   * the other one invoke-virtual {v4, v5} ... So what matters is the (same) target register.
   *
   * @param rs the RegisterSearch to search
   * @return null if previously performed.
   */
  private RegisterSearch linkDuplicateTracks(final RegisterSearch rs) {
    for (final RegisterSearch rs2 : registerQueueDone) {
      if (checkRsForEquality(rs, rs2)) {
        LOGGER.debug("linkDuplicateTracks: Already searched this RS. There is no need to track it again.");

        Collection<SliceNode> sliceNodes = slicer.getCurrentSliceTree().getSliceNodes().values();
        SliceNode followUpNode = Iterables.find(sliceNodes, new Predicate<SliceNode>() {
          public boolean apply(SliceNode arg) {
              /*
               * Look for a linked node that matches a previously tracked RegisterSearch in the following aspects:
               * - The target register is the same as now (or before with rs2, respectively).
               * - The originating properties (previousRegister, previousSliceNode) correspond to the previously tracked object.
               * - The followUpNode needs to be in the same BB as the one we were previously about to track.
               *
               * This last assumption is somewhat bogus because, in theory, it is possible that the BB was just
               * traversed and followUpNode has been found in the subsequent BB. However, we need this check in order
               * to select the "correct" followUpNode, out of multiple available.
               */
            if (rs2.getPreviousRegister() == null)
              return false;

            Set<SliceNode> linkNodes = arg.getLinksFrom().get(new String(rs2.getPreviousRegister()), new String(rs2.getRegister()));

            return (linkNodes != null && linkNodes.contains(rs2.getPreviousSliceNode()) &&
                arg.getBasicBlock() != null && arg.getBasicBlock().equals(rs2.getBB()) &&
                !arg.getCodeLine().equals(rs.getPreviousSliceNode().getCodeLine())); // avoids self-cycles
          }
        }, null);

        // followUpNode is null if no node followed the looked up RegisterSearch
        if (followUpNode != null)
          followUpNode.addLinkFrom(rs.getPreviousRegister(), rs.getRegister(), rs.getPreviousSliceNode());

        // Return null so that this RS is not tracked anew.
        return null;
      }
    }

    return rs;
  }

  /**
   * Add new field to search.
   * @param cf class, field
   * @param fuzzyLevel
   * @param fuzzyLevelOffset
   * @param path
   * @return true if this was not yet searched through, create a new object, you'll get inconsistencies if you'll reuse the same object
   */
  public boolean addField(byte[][] cf, int fuzzyLevel, int fuzzyLevelOffset, LinkedList<BasicBlock> path,
                          SliceNode previousSliceNode, byte[] previousRegister) {
    LOGGER.debug(" -> Add FIELD: {}.{}\tfuzzy={}/{}", new String(cf[0]), new String(cf[1]), fuzzyLevel, fuzzyLevelOffset);

    if (fuzzyLevel+fuzzyLevelOffset > MAX_FUZZY_LEVEL) {
      LOGGER.debug("    Maximum fuzzy level reached (" + MAX_FUZZY_LEVEL + "): aborting.");
      return false;
    }

    if (fuzzyLevelOffset < MAX_FUZZY_LEVEL-2) {
      LOGGER.debug("    Setting fuzzy offset to " + (MAX_FUZZY_LEVEL-2));
      fuzzyLevelOffset = MAX_FUZZY_LEVEL-2;
    }

    ClassContentTracker ctt = new ClassContentTracker(cf, fuzzyLevel, fuzzyLevelOffset, path, previousSliceNode, previousRegister);
    if (fieldQueue.contains(ctt)) return false;
    if (fieldQueueDone.contains(ctt)) return false;
    fieldQueue.add(ctt);

    return true;
  }

  public ClassContentTracker getNextField() {
    if (fieldQueue.isEmpty())
      return null;

    ClassContentTracker ctt = fieldQueue.remove();
    fieldQueueDone.add(ctt);

    LOGGER.debug("\n\n-> TRACKING FIELD: {}.{}\tfuzzy={}/{}",
        new String(ctt.getCi()[0]), new String(ctt.getCi()[1]), ctt.getFuzzyLevel(), ctt.getFuzzyOffset());

    return ctt;
  }

  /**
   * Add a new array field instance where accesses to are searched later on.
   * @param ca: class, array-field-name
   * @param fuzzyLevel
   * @param path, create a new object, you'll get inconsistencies if you'll reuse the same object
   * @throws SyntaxException
   */
  public boolean addArrayFieldToTrack(byte[][] ca, int fuzzyLevel, int fuzzyLevelOffset, LinkedList<BasicBlock> path,
                                      SliceNode previousSliceNode, byte[] previousRegister) throws SyntaxException {
    LOGGER.debug(" -> Add ARRAY FIELD: {}.{}\tfuzzy={}/{}", new String(ca[0]), new String(ca[1]), fuzzyLevel, fuzzyLevelOffset);

    if (fuzzyLevel+fuzzyLevelOffset > MAX_FUZZY_LEVEL) {
      LOGGER.debug("    Maximum fuzzy level reached ("+MAX_FUZZY_LEVEL+"): aborting.");
      return false;
    }

    if (fuzzyLevelOffset < MAX_FUZZY_LEVEL-2) {
      LOGGER.debug("    Setting fuzzy offset to "+(MAX_FUZZY_LEVEL-2));
      fuzzyLevelOffset = MAX_FUZZY_LEVEL-2;
    }

    ClassContentTracker ctt = new ClassContentTracker(ca, fuzzyLevel, fuzzyLevelOffset, path, previousSliceNode, previousRegister);
    if (arrayQueue.contains(ctt)) return false;
    if (arrayQueueDone.contains(ctt)) return false;
    arrayQueue.add(ctt);

    return true;
  }

  public ClassContentTracker getNextCaToTrack() {
    if (arrayQueue.isEmpty())
      return null;

    ClassContentTracker ctt = arrayQueue.remove();
    arrayQueueDone.add(ctt);

    LOGGER.debug("\n\n-> TRACKING ARRAY FIELD: {}.{}\tfuzzy={}/{}",
        new String(ctt.getCi()[0]), new String(ctt.getCi()[1]), ctt.getFuzzyLevel(), ctt.getFuzzyOffset());

    return ctt;
  }

  /**
   * Add new method to search.
   * @param cm
   * @param fuzzyLevel
   * @param fuzzyLevelOffset
   * @param path
   * @return true if this was not yet searched through, create a new object, you'll get inconsistencies if you'll reuse the same object
   */
  public boolean addReturnValuesFromMethod(byte[][] cm, int fuzzyLevel, int fuzzyLevelOffset,LinkedList<BasicBlock> path,
                                           SliceNode previousSliceNode, byte[] previousRegister) {
    LOGGER.debug(" -> Add RETURN VALUE: {}.{}\tfuzzy={}/{}", new String(cm[0]), new String(cm[1]), fuzzyLevel, fuzzyLevelOffset);

    if (fuzzyLevel+fuzzyLevelOffset > MAX_FUZZY_LEVEL) {
      LOGGER.debug("    Maximum fuzzy level reached (" + MAX_FUZZY_LEVEL + "): aborting.");
      return false;
    }

    ClassContentTracker ctt = new ClassContentTracker(cm, fuzzyLevel, fuzzyLevelOffset, path, previousSliceNode, previousRegister);
    if (returnValueQueue.contains(ctt)) return false;
    if (returnValueQueueDone.contains(ctt)) return false;
    returnValueQueue.add(ctt);

    return true;
  }

  public ClassContentTracker getNextReturnValuesFromMethod() {
    if (returnValueQueue.isEmpty())
      return null;

    ClassContentTracker ctt = returnValueQueue.remove();
    returnValueQueueDone.add(ctt);

    LOGGER.debug("\n\n-> TRACKING RETURN VALUE: {}.{}\tfuzzy={}/{}",
        new String(ctt.getCi()[0]), new String(ctt.getCi()[1]), ctt.getFuzzyLevel(), ctt.getFuzzyOffset());

    return ctt;
  }

  public boolean isFinished() {
    return (registerQueue.isEmpty() && !hasRemainingReturnValuesFromMethods() && !hasRemainingFieldsToTrack() &&
        !hasRemainingArraysToTrack());
  }

  public boolean hasRemainingReturnValuesFromMethods() {
    return !returnValueQueue.isEmpty();
  }

  public boolean hasRemainingFieldsToTrack() {
    return !fieldQueue.isEmpty();
  }

  public boolean hasRemainingArraysToTrack() {
    return !arrayQueue.isEmpty();
  }

  /**
   * Returns the amount of finished RS searches.
   * @return
   */
  public int getFinishedRsCount() {
    return registerQueueDone.size();
  }

  public static class RegisterSearch {
    private byte[] register;
    private final byte[][] fieldInRegister;
    private final BasicBlock bb;
    private final int index;
    private final int fuzzyLevel;
    private int fuzzyOffset;
    private LinkedList<BasicBlock> path;
    private SliceNode previousSliceNode;
    private byte[] previousRegister;

    /**
     * A helper class to backtrack a register.
     * @param register the registername to backtrack, eg, v0.
     * @param bb the {@linkplain BasicBlock} to backtrack
     * @param index the index where to start backtracking inside the BasicBlock
     * @param fuzzyLevel set this to >1 if the search gets noisy, eg, if you are backtracking into the blue for unknown method calls and are interested in the parameters from such a call
     * @param fuzzyOffset
     * @param path the path through the BBs of this search, create a new object, you'll get inconsistencies if you'll reuse the same object
     */
    public RegisterSearch(byte[] register, BasicBlock bb, int index, int fuzzyLevel, int fuzzyOffset, LinkedList<BasicBlock> path,
                          SliceNode previousSliceNode, byte[] previousRegister) {
      this.register = register;
      this.fieldInRegister = null;
      this.bb = bb;
      this.index = index;
      this.fuzzyLevel = fuzzyLevel;
      this.fuzzyOffset = fuzzyOffset;
      this.path = path;
      this.previousSliceNode = previousSliceNode;
      this.previousRegister = previousRegister;
    }

    public RegisterSearch(byte[] register, byte[][] fieldInRegister, BasicBlock bb, int index, int fuzzyLevel,
                          int fuzzyOffset, LinkedList<BasicBlock> path, SliceNode previousSliceNode, byte[] previousRegister) {
      this.register = register;
      this.fieldInRegister = fieldInRegister;
      this.bb = bb;
      this.index = index;
      this.fuzzyLevel = fuzzyLevel;
      this.fuzzyOffset = fuzzyOffset;
      this.path = path;
      this.previousSliceNode = previousSliceNode;
      this.previousRegister = previousRegister;
    }

    /**
     * The register to track backwards.
     * @return
     */
    public byte[] getRegister() {
      return register;
    }

    public byte[][] getFieldInRegister() { return fieldInRegister; }

    /**
     * The BB which holds all instructions
     */
    public BasicBlock getBB() {
      return bb;
    }

    /**
     * The index of the opcode from which the register is tracked. It points to the previously found codeline where the
     * search 'stopped' and this RS was created. However, it is a relative value as it refers to the current BB only.
     *
     * @return
     */
    public int getIndex() {
      return index;
    }

    public int getIndexAbsolute() {
      int actualLineAbsolute = index;

      if (actualLineAbsolute < 0)
        actualLineAbsolute = 0;
      else if (actualLineAbsolute >= bb.getCodeLines().size())
        actualLineAbsolute = bb.getCodeLines().size()-1;

      return actualLineAbsolute;
    }

    /**
     * Was this a fuzzy search. If so, the Results may be (very) inaccurate.
     * @return 0 for a non-fuzzy search. Higher values means more fuzziness
     */
    public int getFuzzyLevel() {
      return fuzzyLevel;
    }

    public int getFuzzyOffset() {
      return fuzzyOffset;
    }

    /**
     * This method sets an offset to the fuzzy value. If the offset
     * plus the fuzzy is too high, the search will be aborted.
     * @param offset
     */
    public void setFuzzyOffset(int offset) {
      fuzzyOffset = offset;
    }

    /**
     * The BB path through the program for this search.
     * @return the path
     */
    public LinkedList<BasicBlock> getPath() {
      return path;
    }

    public SliceNode getPreviousSliceNode() { return previousSliceNode; }

    public void setPreviousSliceNode(SliceNode node) { previousSliceNode = node; }

    public byte[] getPreviousRegister() { return previousRegister; }

    public void setPreviousRegister(byte[] reg) { previousRegister = reg; }
  }

  /**
   * A helper class to identify content of a given class. This may be
   * an array name, a method or a field name.
   */
  public static class ClassContentTracker {
    private final byte[][] ci;
    private final int fuzzyLevel;
    private final int fuzzyLevelOffset;
    private LinkedList<BasicBlock> path;
    private Integer hashCode = null;
    private final SliceNode previousSliceNode;
    private final byte[] previousRegister;

    /**
     * This is a helper class to wrap some content. It can contain arbitrary data,
     * but the first entry of the first parameter must always be the full class
     * name and the second one the identifier of a method, array or field.
     * Further entries are optional and can contain, eg, the parameters for a
     * method and it's return value.
     *
     * @param ci [class, identifier, more optional]
     * @param fuzzyLevel
     * @param fuzzyLevelOffset the offset to the fuzzyLevel
     * @param path2 a new object, you'll get inconsistencies if you'll reuse the same object
     */
    public ClassContentTracker(byte[][] ci, int fuzzyLevel, int fuzzyLevelOffset, LinkedList<BasicBlock> path2,
                               SliceNode previousSliceNode, byte[] previousRegister) {
      this.ci = ci;
      this.fuzzyLevel = fuzzyLevel;
      this.fuzzyLevelOffset = fuzzyLevelOffset;
      this.path = path2;
      this.previousSliceNode = previousSliceNode;
      this.previousRegister = previousRegister;
    }

    /**
     * Get the class and identifier of the class content (array, method or field name)
     * and other optional data.
     *
     * @return ci, ci[0]=full class name, ci[1]=identifier (ci[2+] are optional and can contain more data)
     */
    public byte[][] getCi() {
      return ci;
    }

    /**
     * Is the search fuzzy, that means inaccurate?
     *
     * @return 0 if it is not fuzzy, or a number > 0 for a fuzzy search
     */
    public int getFuzzyLevel() {
      return fuzzyLevel;
    }

    public int getFuzzyOffset() {
      return fuzzyLevelOffset;
    }

    /**
     * The path through the program for this search, the list is always a new copy of the original list.
     * Changes to the returned list will not effect the internal list!
     *
     * @return the path
     */
    public LinkedList<BasicBlock> getPath() {
      return new LinkedList<>(path);
    }

    public SliceNode getPreviousSliceNode() {
      return previousSliceNode;
    }

    public byte[] getPreviousRegister() {
      return previousRegister;
    }

    @Override
    public boolean equals(Object other) {
      if (!(other instanceof ClassContentTracker))
        return false;

      // Check the arrays for equality
      if (ci.length != ((ClassContentTracker)other).ci.length)
        return false;

      if (!Arrays.deepEquals(ci, ((ClassContentTracker) other).ci))
        return false;

      return true;
    }

    @Override
    public int hashCode() {
      if (hashCode == null)
        hashCode = Arrays.deepHashCode(ci);

      return hashCode;
    }

    @Override
    public String toString() {
      String out = "ci=";

      for (byte[] b : ci) {
        out += new String(b);
        out += " ";
      }

      out += ", fuzzy=" + fuzzyLevel;
      out += ", pathLen=" + path.size();

      return out;
    }
  }
}
