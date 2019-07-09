package at.tugraz.iaik.cryptoslice.utils;

import at.tugraz.iaik.cryptoslice.analysis.slicing.SliceNode;
import at.tugraz.iaik.cryptoslice.analysis.slicing.SliceTree;
import at.tugraz.iaik.cryptoslice.application.methods.Method;
import com.google.common.collect.Multimap;
import com.google.common.collect.Table;

import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

public class PathFinder {
  /**
   * Find all non-cyclical paths between two vertices.
   *
   * @param currentNode
   * @param endNode
   * @param nodesVisited
   * @param paths
   */
  public static void findAllPathsDFS(SliceNode currentNode, SliceNode endNode, LinkedList<SliceNode> nodesVisited, List<List<SliceNode>> paths) {
    // Make a union of all source links in order not to track them multiple times
    Set<SliceNode> sourceLinks = new HashSet<>();
    for (Set<SliceNode> linkSet : currentNode.getLinksFrom().values()) {
      /*for (final SliceNode node : linkSet) {
        Collection<SliceNode> nodesForMethod = sliceTree.getSliceNodes().get(node.getMethod());
        SliceNode referenceNode = Iterables.find(nodesForMethod, new Predicate<SliceNode>() {
          public boolean apply(SliceNode arg) {
            // All methods have unique line numbers, so this check might be sufficient
            return (arg.getCodeLine().getLineNr() == node.getCodeLine().getLineNr());
          }
        }, null);

        sourceLinks.add(referenceNode);
      }*/

      sourceLinks.addAll(linkSet);
    }

    // Examine adjacent nodes
    for (SliceNode link : sourceLinks) {
      if (nodesVisited.contains(link)) {
        continue;
      }

      // Terminate the search if endNode links to currentNode
      if (link.equals(endNode)) {
        nodesVisited.add(link);
        paths.add(new LinkedList<SliceNode>(nodesVisited));
        nodesVisited.removeLast();
        break;
      }
    }

    // Recursively visit adjacent nodes
    for (SliceNode link : sourceLinks) {
      if (nodesVisited.contains(link) || link.equals(endNode)) {
        continue;
      }

      nodesVisited.add(link);
      findAllPathsDFS(link, endNode, nodesVisited, paths);
      nodesVisited.removeLast();
    }
  }

  public static List<List<SliceNode>> extractAllPathsToLeafs(SliceTree slicetree, SliceNode startNode, Set<SliceNode> leafs) {
    List<List<SliceNode>> paths = new LinkedList<>();
    // Loop through the leafs and fetch all paths
    for (SliceNode leaf : leafs) {
      LinkedList<SliceNode> nodesVisited = new LinkedList<>();
      nodesVisited.add(leaf);

      findAllPathsDFS(leaf, startNode, nodesVisited, paths);
    }

    return paths;
  }

  public static List<List<SliceNode>> extractAllPathsToLeafs(SliceTree slicetree, SliceNode startNode) {
    // First filter all leafs
    Set<SliceNode> leafs = getLeafs(slicetree);

    return extractAllPathsToLeafs(slicetree, startNode, leafs);
  }

  public static Set<SliceNode> getLeafs(SliceTree slicetree) {
    Multimap<Method, SliceNode> sliceNodes = slicetree.getSliceNodes();

    // TODO: This is very inefficient. Better: Extract all nodes that are not in any others' links and different to the start node.
    Set<SliceNode> leafs = new HashSet<>();
    for (SliceNode n : sliceNodes.values()) {
      leafs.add(n);
    }

    for (SliceNode node : sliceNodes.values()) {
      Table<String, String, Set<SliceNode>> links = node.getLinksFrom();
      for (Set<SliceNode> s : links.values()) {
        leafs.removeAll(s);
      }
    }

    return leafs;
  }
}
