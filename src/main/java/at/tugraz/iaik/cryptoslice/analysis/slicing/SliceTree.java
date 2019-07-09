package at.tugraz.iaik.cryptoslice.analysis.slicing;

import at.tugraz.iaik.cryptoslice.application.instructions.Constant;
import at.tugraz.iaik.cryptoslice.application.methods.BasicBlock;
import at.tugraz.iaik.cryptoslice.application.methods.Method;
import com.google.common.base.Predicate;
import com.google.common.collect.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;

public class SliceTree {
  private static final Logger LOGGER = LoggerFactory.getLogger(SliceTree.class);
  private final Multimap<Method, SliceNode> sliceNodes = MultimapBuilder.linkedHashKeys().treeSetValues().build();
  private SliceNode startNode = null;
  private boolean treeFinalized = false;

  public void addConstant(Constant constant, BasicBlock bb, SliceNode link, byte[] previousRegister) {
    final SliceNode node = new SliceNode(constant, bb, link, previousRegister);

    Collection<SliceNode> nodesForMethod = sliceNodes.get(constant.getCodeLine().getMethod());
    SliceNode existingNode = Iterables.find(nodesForMethod, new Predicate<SliceNode>() {
      public boolean apply(SliceNode arg) {
        // All methods have unique line numbers, so this check might be sufficient
        return (arg.getCodeLine().getLineNr() == node.getCodeLine().getLineNr());
      }
    }, null);

    if (existingNode != null) {
      existingNode.setConstant(constant);
    } else {
      if (sliceNodes.isEmpty())
        startNode = node;

      sliceNodes.put(constant.getCodeLine().getMethod(), node);
    }
  }

  public SliceNode addNode(TodoList.RegisterSearch rs) {
    final SliceNode node = new SliceNode(rs);

    if (sliceNodes.containsEntry(rs.getBB().getMethod(), node)) {
      /*
       * Add the predecessor as link.
       * The if-clause should always match actually because there can not
       * be a subsequent node with no source link.
       */
      if (rs.getPreviousSliceNode() != null) {
        LOGGER.debug("addNode (existing): line {} (reg {}) linked from {} (reg {})",
            node.getCodeLine().getLineNr(), new String(rs.getRegister()),
            rs.getPreviousSliceNode().getCodeLine().getLineNr(), new String(rs.getPreviousRegister()));

        Collection<SliceNode> nodesForMethod = sliceNodes.get(rs.getBB().getMethod());
        SliceNode existingNode = Iterables.find(nodesForMethod, new Predicate<SliceNode>() {
          public boolean apply(SliceNode arg) {
            // All methods have unique line numbers, so this check might be sufficient
            return (arg.getCodeLine().getLineNr() == node.getCodeLine().getLineNr());
          }
        });

        /*
         * When the node was previously inserted as constant and is now further tracked (i.e. external function),
         * the link, where table column "const" is, gets removed because the link (added below)
         * contains not only source but also the target register.
         */
        if (existingNode.getConstant() != null)
          existingNode.getLinksFrom().column("const").clear();

        // existingNode can not be null because it was previously found during containsEntry()
        existingNode.addLinkFrom(rs.getPreviousRegister(), rs.getRegister(), rs.getPreviousSliceNode());
      }
    } else {
      // A new node is inserted. If it is not the first entry, it has one link
      if (rs.getPreviousSliceNode() != null) {
        LOGGER.debug("addNode (new): line {} (reg {}) linked from {} (reg {})",
            node.getCodeLine().getLineNr(), new String(rs.getRegister()),
            rs.getPreviousSliceNode().getCodeLine().getLineNr(), new String(rs.getPreviousRegister()));

        node.addLinkFrom(rs.getPreviousRegister(), rs.getRegister(), rs.getPreviousSliceNode());
      } else if (sliceNodes.isEmpty()) { // This node is the initial one
        startNode = node;
      }

      sliceNodes.put(rs.getBB().getMethod(), node);
    }

    return node;
  }

  /**
   * Every slice tree needs post-processing in order to update sliceNode links.
   *
   * Assuming node B adds a "link from" node A, it actually saves a reference to node A.
   * When A is re-accessed later "addNode (existing)" in order to replace a "const" statement or to add
   * another link to A, obviously the reference in node B is automatically deep-copied _before_ node A gets modified.
   * Presumably, the JVM thinks that it is intended to keep the state of the previously added object unchanged.
   * As a result, we end with two versions of node A. An outdated one is present as a link in node B,
   * an updated one is still contained as a node in the sliceNodes object.
   *
   * Since the outdated node A now lacks further added information, we get incomplete graph paths.
   * The solution is to replace all (probably - but not necessarly) outdated "link from" nodes with their
   * current / updated version from the sliceNodes object. In other words, we discard the outdated node.
   */
  private void updateReferences() {
    Collection<SliceNode> nodes = sliceNodes.values();

    for (SliceNode currentNode : nodes) {
      Table<String, String, Set<SliceNode>> updatedLinksFrom = HashBasedTable.create();

      for (Table.Cell<String, String, Set<SliceNode>> links : currentNode.getLinksFrom().cellSet()) {
        Set<SliceNode> updatedLinkSet = new HashSet<>();

        for (final SliceNode linkNode : links.getValue()) {
          Collection<SliceNode> nodesForLinkMethod = sliceNodes.get(linkNode.getMethod());
          SliceNode updatedLinkNode = Iterables.find(nodesForLinkMethod, new Predicate<SliceNode>() {
            public boolean apply(SliceNode arg) {
              // All methods have unique line numbers, so this check might be sufficient
              return (arg.getCodeLine().getLineNr() == linkNode.getCodeLine().getLineNr());
            }
          });

          updatedLinkSet.add(updatedLinkNode);
        }

        updatedLinksFrom.put(links.getRowKey(), links.getColumnKey(), updatedLinkSet);
      }

      currentNode.setLinksFrom(updatedLinksFrom);
    }

    treeFinalized = true;
  }

  public Multimap<Method, SliceNode> getSliceNodes() {
    if (!treeFinalized) {
      updateReferences();
    }

    return sliceNodes;
  }

  public SliceNode getStartNode() { return startNode; }
}
