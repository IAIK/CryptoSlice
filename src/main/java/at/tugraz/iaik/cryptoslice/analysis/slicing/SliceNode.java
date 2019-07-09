package at.tugraz.iaik.cryptoslice.analysis.slicing;

import at.tugraz.iaik.cryptoslice.application.CodeLine;
import at.tugraz.iaik.cryptoslice.application.instructions.Constant;
import at.tugraz.iaik.cryptoslice.application.methods.BasicBlock;
import at.tugraz.iaik.cryptoslice.application.methods.Method;
import com.google.common.base.Objects;
import com.google.common.collect.HashBasedTable;
import com.google.common.collect.Table;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.HashSet;
import java.util.Set;

public class SliceNode implements Comparable<SliceNode> {
  private static final Logger LOGGER = LoggerFactory.getLogger(SliceNode.class);

  /*
   * The predecessor nodes of this node may originate from the same register and also target the same register.
   * For example, <p1, p1, Predecessor node> can occur multiple times. Thus, we need a Set<SliceNode>.
   *
   * In fact we would need a Table backed by a Multimap (Table<Multimap<R, Map<C, V).
   * However, a Multitable is currently not possible with Guava.
   */
  private Table<String, String, Set<SliceNode>> linksFrom = HashBasedTable.create();
  private final CodeLine codeLine;
  private final BasicBlock basicBlock;
  private Constant constant = null;

  public SliceNode(TodoList.RegisterSearch rs) {
    // Get the code line
    codeLine = rs.getBB().getCodeLines().get(rs.getIndexAbsolute());
    basicBlock = rs.getBB();
  }

  public SliceNode(Constant constant, BasicBlock bb, SliceNode link, byte[] previousRegister) {
    this.constant = constant;
    codeLine = constant.getCodeLine();
    basicBlock = bb;

    // If a constant is added right after the search start, there might be no previousRegister yet.
    if (previousRegister != null) {
      LOGGER.debug("SliceNode const: {} linked from {} (reg {})", codeLine.getLineNr(), link.getCodeLine().getLineNr(),
          new String(previousRegister));
      addLinkFrom(previousRegister, "const".getBytes(), link);
    }
  }

  public void addLinkFrom(byte[] previousRegister, byte[] currentRegister, SliceNode link) {
    String prev = (previousRegister != null) ? new String(previousRegister) : "";
    String curr = (currentRegister != null) ? new String(currentRegister) : "";

    Set<SliceNode> nodes = linksFrom.get(prev, curr);
    if (nodes == null)
      nodes = new HashSet<>();
    nodes.add(link);

    linksFrom.put(prev, curr, nodes);
  }

  public String getIdentifier() {
    return codeLine.toString();
  }

  public Method getMethod() {
    return codeLine.getMethod();
  }

  public CodeLine getCodeLine() {
    return codeLine;
  }

  public Table<String, String, Set<SliceNode>> getLinksFrom() {
    return linksFrom;
  }

  public void setLinksFrom(Table<String, String, Set<SliceNode>> linksFrom) {
    this.linksFrom = linksFrom;
  }

  public BasicBlock getBasicBlock() { return basicBlock; }

  public Constant getConstant() {
    return constant;
  }

  public void setConstant(Constant constant) {
    this.constant = constant;
  }

  @Override
  public int compareTo(SliceNode other) {
    // The following check is sufficient due to the fact that SliceNode objects are inserted per method in SliceTree.
    return Integer.compare(this.codeLine.getLineNr(), other.codeLine.getLineNr());
  }

  @Override
  public int hashCode() {
    // You must not use linksFrom here or else: Stackoverflow!
    return Objects.hashCode(codeLine, basicBlock);
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj)
      return true;

    if (obj == null || getClass() != obj.getClass())
      return false;

    final SliceNode other = (SliceNode) obj;
    return Objects.equal(this.codeLine, other.codeLine)
        && Objects.equal(this.basicBlock, other.basicBlock);
  }
}
