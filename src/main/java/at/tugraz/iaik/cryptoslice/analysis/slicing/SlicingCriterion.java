package at.tugraz.iaik.cryptoslice.analysis.slicing;

import at.tugraz.iaik.cryptoslice.application.instructions.Constant;
import com.google.common.collect.HashMultimap;
import com.google.common.collect.Multimap;

import java.util.HashMap;
import java.util.LinkedList;
import java.util.Map;

/**
 * This class describes the entry point for the program slicing algorithm.
 * It defines a method within in a class and a parameter which is then
 * backtracked in order to build def-use chains and find used constants
 * which are used as input for the defined parameter.
 */
public class SlicingCriterion {
  private SlicingPattern pattern;
  private final Map<Integer, SliceTree> sliceTrees = new HashMap<>();
  private final Multimap<Integer, Constant> sliceConstants = HashMultimap.create();
  private final LinkedList<Throwable> exceptionList = new LinkedList<>();

  public SlicingCriterion(SlicingPattern pattern) {
    this.pattern = pattern;
  }

  public SlicingCriterion() { }

  /**
   * Add a new Constant. Duplicates are ignored.
   *
   * @param constant
   */
  public void addFoundConstant(int searchId, Constant constant) {
    sliceConstants.put(searchId, constant);
  }

  public SlicingPattern getPattern() { return pattern; }

  public void setPattern(SlicingPattern pattern) { this.pattern = pattern; }

  public Multimap<Integer, Constant> getSliceConstants() {
    return sliceConstants;
  }

  public Map<Integer, SliceTree> getSliceTrees() { return sliceTrees; }

  public void addToSliceTress(int searchId, SliceTree currentSliceTree) {
    sliceTrees.put(searchId, currentSliceTree);
  }

  /**
   * Get all logged exceptions.
   *
   * @return the (empty) list of exceptions
   */
  public LinkedList<Throwable> getExceptionList() {
    return exceptionList;
  }

  /**
   * Log an exception which occurred during the backtrack analysis.
   *
   * @param t the exception or error
   */
  public void logException(Throwable t) {
    exceptionList.add(t);
  }
}
