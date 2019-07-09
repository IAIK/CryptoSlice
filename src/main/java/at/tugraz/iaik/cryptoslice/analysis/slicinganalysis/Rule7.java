package at.tugraz.iaik.cryptoslice.analysis.slicinganalysis;

import at.tugraz.iaik.cryptoslice.analysis.Analysis;
import at.tugraz.iaik.cryptoslice.analysis.slicing.*;
import at.tugraz.iaik.cryptoslice.utils.PathFinder;
import at.tugraz.iaik.cryptoslice.application.CodeLine;
import at.tugraz.iaik.cryptoslice.application.DetectionLogicError;
import at.tugraz.iaik.cryptoslice.application.instructions.Constant;
import at.tugraz.iaik.cryptoslice.application.methods.Method;
import com.google.common.base.Predicate;
import com.google.common.collect.Iterables;
import com.google.common.collect.Multimap;
import org.stringtemplate.v4.ST;

import java.util.*;

public class Rule7 extends CryptoRule {
  Rule7(Analysis analysis) {
    super(analysis);
  }

  @Override
  public String check() throws DetectionLogicError {
    LOGGER.debug("\n\n## Checking Rule 7: No MessageDigest without content");
    ruleReport.addAggr("ruleHead.{number, title}", 7, "No MessageDigest without content");

    SlicingPatternFT pattern1 = new SlicingPatternFT("java/security/MessageDigest", "getInstance", "OBJECT", "");
    SlicingCriterion criterion = new SlicingCriterion(pattern1);
    SlicerForward slicer = new SlicerForward(analysis.getApp(), searchIds);
    slicer.startSearch(criterion);

    if (criterion.getSliceConstants().isEmpty()) {
      LOGGER.info("Abort: No MessageDigest or no constants found!");
      ruleReport.add("abortMsg", "No MessageDigest or no constants found!");
      return ruleReport.render();
    }

    /*
     * Not detectable:
     * a) Tracking from PUT to the following lines:
     * 48: iget-object v0, p0, Lorg/apache/http/impl/auth/NTLMEngineImpl$HMACMD5;->md5:Ljava/security/MessageDigest;
     * 50: invoke-virtual {v0}, Ljava/security/MessageDigest;->digest()[B
     * when the preceding lines are something like:
     * 44: iget-object v0, p0, Lorg/apache/http/impl/auth/NTLMEngineImpl$HMACMD5;->md5:Ljava/security/MessageDigest;
     * 46: invoke-virtual {v0, p1}, Ljava/security/MessageDigest;->update([B)V
     *
     * b) The register is copied and treated as a reference:
     * 494: invoke-static {v5}, Ljava/security/MessageDigest;->getInstance(Ljava/lang/String;)Ljava/security/MessageDigest;
     * 498: move-result-object v20
     * 511: move-object/from16 v1, v20
     * 513: invoke-direct {v11, v0, v1}, Ljava/security/DigestOutputStream;-><init>(Ljava/io/OutputStream;Ljava/security/MessageDigest;)V
     * 525: invoke-virtual/range {v20 .. v20}, Ljava/security/MessageDigest;->digest()[B
     * -> The path from getInstance to digest does not include v1 or anything related to v1. It is not obvious to see
     * that there is actually a relation between DigestOutputStream and digest.
     */

    for (Integer searchId : criterion.getSliceConstants().keySet()) {
      CodeLine startLine = searchIds.get(searchId);
      LOGGER.info("\nFound MessageDigest in method " + startLine.getMethod().getReadableJavaName() + " in line " +
          startLine.getLineNr());

      ST messageDigestReport = analysis.getReport().getTemplate("Rule7_MessageDigest");
      messageDigestReport.addAggr("info.{method, codeline}", startLine.getMethod().getReadableJavaName(), startLine.getLineNr());

      Collection<Constant> constants = criterion.getSliceConstants().get(searchId);
      SliceTree tree = criterion.getSliceTrees().get(searchId);

      /*
       * Look for "MessageDigest->digest()" nodes (having no parameter!)
       * One forward slice may contain multiple digest() invokes, based on the same MessageDigest object.
       */
      Multimap<Method, SliceNode> sliceNodes = tree.getSliceNodes();
      Iterable<SliceNode> digestNodes = Iterables.filter(sliceNodes.values(), new Predicate<SliceNode>() {
        public boolean apply(SliceNode arg) {
          return (arg.getConstant() != null && arg.getConstant().getValue() != null &&
              arg.getConstant().getValue().equals("java/security/MessageDigest->digest()"));
        }
      });

      if (Iterables.isEmpty(digestNodes)) {
        LOGGER.debug("No MessageDigest->digest() found!");
        messageDigestReport.add("abortMsg", "No MessageDigest->digest() found!");
        ruleReport.add("searchIds", messageDigestReport);
        continue;
      }

      for (SliceNode digestNode : digestNodes) {
        List<List<SliceNode>> paths = new ArrayList<>();
        LinkedList<SliceNode> nodesVisited = new LinkedList<>();
        nodesVisited.add(digestNode);

        // Find all paths from the current digest() object up to MessageDigest->getInstance()
        PathFinder.findAllPathsDFS(digestNode, tree.getStartNode(), nodesVisited, paths);

        // Check for all paths if they contain a call to MessageDigest->update()
        for (List<SliceNode> path : paths) {
          boolean foundUpdate = false;
          Collections.reverse(path);
          for (SliceNode currentNode : path) {
            //System.out.println(currentNode.getCodeLine());
            if (currentNode.getConstant() != null && currentNode.getConstant().getValue() != null) {
              if (currentNode.getConstant().getValue().startsWith("java/security/MessageDigest->update("))
                foundUpdate = true;
              else if (currentNode.getConstant().getValue().startsWith("java/security/MessageDigest->reset()"))
                foundUpdate = false;
            }
          }

          // Verify that there was an update(...) call and that no reset() before digest()
          if (!foundUpdate) {
            // Look for DigestOutputStream to prevent an occasional wrong alert
            boolean foundDigestOutputStream = false;
            for (Constant constant : constants) {
              if (constant.getValue() != null &&
                  constant.getValue().startsWith("java/security/DigestOutputStream-><init>(")) {
                foundDigestOutputStream = true;
                break;
              }
            }

            if (foundDigestOutputStream)
              continue;

            LOGGER.warn("ALERT: Probably found a path with no MessageDigest->update()!");
            ST messageDigestPathReport = analysis.getReport().getTemplate("Rule7_MessageDigestPath");
            for (SliceNode currentNode : path) {
              LOGGER.warn(currentNode.getMethod().getSmaliClass().getFullClassName(true) + ": " + currentNode.getCodeLine());
              messageDigestPathReport.add("element", currentNode.getMethod().getSmaliClass().getFullClassName(true) + ": " + currentNode.getCodeLine());
            }

            LOGGER.warn("");
            messageDigestReport.add("messageDigestPaths", messageDigestPathReport.render());
          }
        }
      }

      /*for (Constant constant : constants)
        System.out.println("RAW: " + constant.toString());*/

      ruleReport.add("searchIds", messageDigestReport);
    }

    return ruleReport.render();
  }


}