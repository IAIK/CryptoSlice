package at.tugraz.iaik.cryptoslice.analysis.slicing;

import at.tugraz.iaik.cryptoslice.application.Application;
import at.tugraz.iaik.cryptoslice.application.CodeLine;
import at.tugraz.iaik.cryptoslice.application.DetectionLogicError;
import at.tugraz.iaik.cryptoslice.application.SmaliClass;
import at.tugraz.iaik.cryptoslice.application.methods.Method;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public abstract class Slicer {
  protected final Logger LOGGER = LoggerFactory.getLogger(getClass());

  protected final Application app;
  protected SlicingCriterion criterion;
  protected TodoList todoList;
  protected SliceTree currentSliceTree;

  // This holds the class, the method and its parameters we are currently searching for
  protected byte[][] cmp = new byte[3][];

  /**
   * Each constant that is found for a specific start point (codeLine) gets assigned the same searchId. This is useful
   * to find constants which are part of one method invocation but are used as different method parameters. The same
   * method invocation in different parts of the code will have a different searchId.
   * Eg.: sentTextMessage(no, ..., text, ...)
   */
  protected int searchId;
  protected final List<CodeLine> searchIds;

  protected static final int MAX_ITERATIONS = Integer.MAX_VALUE;
  protected static final byte[] P0_THIS = "p0".getBytes();
  protected static final byte[] WILDCARD = { '*' };

  protected Slicer(Application app, List<CodeLine> searchIds) {
    this.app = app;
    this.searchIds = searchIds;
  }

  protected abstract void startSearch(SlicingCriterion criterion) throws DetectionLogicError;

  protected abstract void startTracking() throws DetectionLogicError;

  protected SliceTree getCurrentSliceTree() { return currentSliceTree; }

  public List<Method> findMethod(byte[][] cmp) {
    List<Method> methodList = new ArrayList<>();

    List<SmaliClass> smaliClasses = app.getAllSmaliClasses();
    for (SmaliClass smaliClass : smaliClasses) {
      // First check if the right class is investigated or if a wildcard is set
      if (Arrays.equals(cmp[0], smaliClass.getFullClassName(false).getBytes()) || Arrays.equals(cmp[0], WILDCARD)) {
        // Check if the given method exists (by method name)
        Method currentMethod = smaliClass.getMethodByName(new String(cmp[1]));
        if (currentMethod != null) {
          // Check the parameter list
          if (cmp[2] == null || Arrays.equals(cmp[2], currentMethod.getParameters())) {
            methodList.add(currentMethod);
          }
        }
      }
    }

    return methodList;
  }
}
