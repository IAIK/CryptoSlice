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

import at.tugraz.iaik.cryptoslice.application.*;
import at.tugraz.iaik.cryptoslice.application.instructions.InstructionType;
import at.tugraz.iaik.cryptoslice.utils.ByteUtils;
import at.tugraz.iaik.cryptoslice.utils.KMP;
import com.google.common.collect.ComparisonChain;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;

public class Method implements Comparable<Method> {
  private static final Logger LOGGER = LoggerFactory.getLogger(Method.class);

  private final LinkedList<CodeLine> codeLines;
  private final SmaliClass smaliClass;
  private final int label;

  private enum METHOD_TYPE {
    CONSTRUCTOR, STATIC_CONSTRUCTOR, // static { ... } block
    METHOD // all other "normal" methods
  }
  private static final byte[] CONSTRUCTOR_NAME = "<init>".getBytes();
  public static final byte[] STATIC_CONSTRUCTOR_NAME = "<clinit>".getBytes();
  private METHOD_TYPE methodType;
  private String name;
  private String parameters = null;
  private String returnValueString = null;
  private boolean isStatic = false;
  private boolean isNative = false;
  private boolean isPrivate = false;
  private boolean isCurrentLineInSwitch = false;
  private byte[] rawParameters;
  private byte[] returnValue;
  private boolean hasUnlinkedBBs = false;
  private List<BasicBlock> bbList = new LinkedList<>();

  public Method(LinkedList<CodeLine> codeLines, SmaliClass smaliClass, int label) {
    this.codeLines = codeLines;
    this.smaliClass = smaliClass;
    this.label = label;

    parseNameAndType();
  }

  private void parseNameAndType() {
    // ex: .method public constructor <init>(Landroid/content/Context;)V
    // or: .method public native unlock(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;
    byte[] methodSig = codeLines.getFirst().getLine();
    int parameterStartIndex = ByteUtils.indexOf(methodSig, '(');
    int parameterEndIndex = ByteUtils.indexOf(methodSig, ')');
    int accessModifierEndIndex = ByteUtils.indexOfReverse(methodSig, ' ', parameterStartIndex);

    byte[] methodName = ByteUtils.subbytes(methodSig, accessModifierEndIndex+1, parameterStartIndex); // cut the space
    name = new String(methodName);
    if (Arrays.equals(methodName, CONSTRUCTOR_NAME))
      methodType = METHOD_TYPE.CONSTRUCTOR;
    else if (Arrays.equals(methodName, STATIC_CONSTRUCTOR_NAME))
      methodType = METHOD_TYPE.STATIC_CONSTRUCTOR;
    else
      methodType = METHOD_TYPE.METHOD;

    // Check if the method is static, only use the first part because the method
    // could have the word static in its name.
    byte[] accessModifier = ByteUtils.subbytes(methodSig, 0, accessModifierEndIndex);
    if (ByteUtils.contains(accessModifier, "static".getBytes()))
      isStatic = true;

    if (ByteUtils.contains(accessModifier, "native".getBytes()))
      isNative = true;

    if (ByteUtils.contains(accessModifier, "private".getBytes()))
      isPrivate = true;

    rawParameters = ByteUtils.subbytes(methodSig, parameterStartIndex + 1, parameterEndIndex);
    returnValue = ByteUtils.subbytes(methodSig,	parameterEndIndex + 1);
  }

  // FIXME: crude hack to replace the autogeneration in parseNameAndType(),
  // could perhaps still always be generated in parseNameAndType (for safety)
  // and use this just for explicitly generating bbs anew
  public void generateBBs() throws DetectionLogicError, SmaliClassError {
    bbList = generateBlocksNew();
    DFS dfs = new DFS();
    dfs.labelAllBB(this);
  }

  private List<BasicBlock> generateBlocksNew() throws SmaliClassError {
    // CHANGE ALL PARAMS TO PASS THE LABELS
    // possibly change everything to index in codeline array instead of codelines

    // Still have to fix problem that switchtable will be part of the last BB
    Map<String, CodeLine> labels = getLabelLines();
    List<Link> links = findLeadersNew();
    List<Integer> leaders = new ArrayList<>();
    links = findGotoTargetsNew(links, labels, leaders);
    links = findIfTargetsNew(links, labels);// instruction.getType() == InstructionType.LABEL and/or isCode
    links = findSwitchTargetsNew(links, labels);
    List<TryCatchBlock> tries = findTryTargetsNew(links, labels);

    // Build blocks from tries + links
    List<BasicBlock> blocks = buildBlocks(links, tries, leaders);
    blocks = linkNew(blocks, links, tries);

    return blocks;
  }

  private HashMap<String, CodeLine> getLabelLines() {
    HashMap<String, CodeLine> labels = new HashMap<String, CodeLine>();

    for (CodeLine cl : codeLines) {
      if (ByteUtils.startsWith(cl.getLine(), ":".getBytes())) {
        String label = new String(cl.getLine());
        if (!labels.containsKey(label))
          labels.put(label, cl);
      }
    }

    return labels;
  }

  /**
   * Check if the line is the end of a BB, so the next Line is a leader.
   *
   * @param cl
   * @return
   */
  private boolean isLeaderNew(CodeLine cl) {
    if (cl.getInstruction().getType() == InstructionType.JMP
        || cl.getInstruction().getType() == InstructionType.SWITCH)
      return true;

    return false;
  }

  // All leaders of the BBs
  private List<Link> findLeadersNew() {
    List<Link> links = new ArrayList<Link>();

    for (int currentLine = 0; currentLine < codeLines.size() - 1; currentLine++) {
      CodeLine cl = codeLines.get(currentLine);
      Link link = new Link(cl, codeLines.get(currentLine + 1));
      if (isLeaderNew(cl) && !links.contains(link))
        links.add(link);
    }

    return links;
  }

  private List<Link> findGotoTargetsNew(List<Link> links, Map<String, CodeLine> labels, List<Integer> leaders) {
    for (int currentLine = 0; currentLine < codeLines.size(); currentLine++) {
      CodeLine cl = codeLines.get(currentLine);

      if (cl.getInstruction().getType() == InstructionType.GOTO) {
        String label = new String(cl.getInstruction().getLabel());

        CodeLine to = labels.get(label);
        Link link = new Link(cl, to);

        if (!links.contains(link))
          links.add(link);

        if (currentLine < codeLines.size() - 1)
          leaders.add(currentLine + 1);
      }
    }

    return links;
  }

  private List<Link> findIfTargetsNew(List<Link> links, Map<String, CodeLine> labels) {

    for (int currentLine = 0; currentLine < codeLines.size(); currentLine++) {
      CodeLine cl = codeLines.get(currentLine);

      if (cl.getInstruction().getType() == InstructionType.JMP) {
        String label = new String(cl.getInstruction().getLabel());

        CodeLine to = labels.get(label);
        Link link = new Link(cl, to);
        if (!links.contains(link))
          links.add(link);

        // fallthrough: need to check if next is switch? probably not, because there is
        // always a fallthrough so compiler should prevent fall to switchtable (would probably result in an error)
        if (currentLine < codeLines.size() - 1) {
          to = codeLines.get(currentLine + 1);
          link = new Link(cl, to);
          if (!links.contains(link))
            links.add(link);
        }
      }
    }

    return links;
  }

  private List<Link> findSwitchTargetsNew(List<Link> links, Map<String, CodeLine> labels) {
    Map<String, List<Target>> switchTablesNew = new HashMap<>();
    Map<String, CodeLine> switchInstructions = new HashMap<>();
    List<Target> tmpList = new ArrayList<Target>();
    String switchName = null;
    boolean inSwitchTable = false;

    for (CodeLine cl : codeLines) {
      // switch start found
      // build association between the switch-statement and the
      // corresponding switch-table
      if (cl.getInstruction().getType() == InstructionType.SWITCH) {
        String tableName = new String(cl.getInstruction().getLabel());

        if (!switchInstructions.containsKey(tableName))
          switchInstructions.put(tableName, cl);
      }
      // switch table BEGIN found
      // if(ByteUtils.startsWith(cl.getLine(), ":switch ".getBytes())){
      // label of current switch tables
      // Table starts in the following line

      // name of the switch table
      // next line is a .sparse/packed_switch, after that , the switches
      // are listed, containing the initial value too compare too
      if (KMP.indexOf(cl.getLine(), ":sswitch_data".getBytes()) == 0
          || KMP.indexOf(cl.getLine(), ":pswitch_data".getBytes()) == 0) {
        switchName = new String(cl.getLine());
        continue;
      }

      // the initial value... in hex
      // example : .packed_switch 0x0
      // -> first one taken if value = 0, second if value 2 etc.
      if (KMP.indexOf(cl.getLine(), ".sparse-switch".getBytes()) == 0
          || KMP.indexOf(cl.getLine(), ".packed-switch".getBytes()) == 0) {
        // initialvalue = end of line (from hex to decimal)
        inSwitchTable = true;
        continue;
      }

      // read table
      // determine which switch label belongs to which switch table
      // condition shoudl be in front of : , target = :blabla
      if (inSwitchTable) {
        // check of end of table first

        // switch table END found
        // end of switch table
        if (KMP.indexOf(cl.getLine(), ".end sparse-switch".getBytes()) == 0
            || KMP.indexOf(cl.getLine(), ".end packed-switch".getBytes()) == 0) {

          // put links into table
          switchTablesNew.put(switchName, tmpList);
          // init new list
          tmpList = new ArrayList<Target>();
          switchName = null;
          inSwitchTable = false;

          continue;
        }

        // if not end of table, make links and put them into the list
        // use switchName for map association
        int start = KMP.indexOf(cl.getLine(), ":".getBytes());
        // targets are starting with a :
        String switchTarget = new String(ByteUtils.subbytes(cl.getLine(), start));
        CodeLine switchTargetLine = labels.get(switchTarget);
        tmpList.add(new Target(switchTargetLine));
      }
    }

    // now that we have seen all the switches, make all the links based on
    // the instructions and corresponding tables
    for (Map.Entry<String, CodeLine> entry : switchInstructions.entrySet()) {
      String key = entry.getKey();
      CodeLine value = entry.getValue();
      List<Target> targets = switchTablesNew.get(key);
      for (Target t : targets)
        links.add(new Link(value, t.getTo()));
    }

    // return all the links
    return links;
  }

  private List<TryCatchBlock> findTryTargetsNew(List<Link> links, Map<String, CodeLine> labels) {
    List<TryCatchBlock> tryList = new ArrayList<TryCatchBlock>();
    TryCatchBlock block = null;
    int begin = -1;
    int end = -1;
    int endOfTryCode = -1;
    boolean findCatches = false;

    for (int currentLine = 0; currentLine < codeLines.size(); currentLine++) {
      CodeLine cl = codeLines.get(currentLine);
      if (findCatches) {
        if (KMP.indexOf(cl.getLine(), ".catch".getBytes()) == 0) {
          // we want the actual CodeLineInterface, so we read the
          // label of the catch block and then look up which CodeLine that is
          CodeLine currentCatchTarget = labels.get(new String(ByteUtils.subbytes(cl.getLine(), ByteUtils.indexOfReverse(cl.getLine(), ':'))));
          block.addCatch(currentCatchTarget);
          end = cl.getLineNr();
          continue;
        } else {
          findCatches = false;
          block.setEnd(end);

          block.setBlockEnd(codeLines.get(currentLine - 1));
          tryList.add(block);
          block = null;

          // add fall through link here?
          // System.out.println("Fall through try link: ");
          if (currentLine < codeLines.size() - 1 && endOfTryCode != -1) {
            Link link = new Link(codeLines.get(endOfTryCode), codeLines.get(currentLine));
            // System.out.println("link...   from: "+link.getFrom()+" to: "+link.getTo());
            links.add(link);
          }
        }
      }

      if (KMP.indexOf(cl.getLine(), ":try_start_".getBytes()) == 0) {
        begin = cl.getLineNr();
        endOfTryCode = -1;
      }

      if (KMP.indexOf(cl.getLine(), ":try_end_".getBytes()) == 0) {
        block = new TryCatchBlock(begin, end);
        findCatches = true;
        endOfTryCode = currentLine - 1;
      }
    }

    return tryList;
  }

  private boolean isSwitchStart(CodeLine cl) {
    if (KMP.indexOf(cl.getLine(), ":sswitch_data".getBytes()) == 0
        || KMP.indexOf(cl.getLine(), ":pswitch_data".getBytes()) == 0) {
      isCurrentLineInSwitch = true;
      return true;
    }

    return false;
  }

  private boolean isInSwitch() {
    return isCurrentLineInSwitch;
  }

  private boolean isSwitchEnd(CodeLine cl) {
    if (KMP.indexOf(cl.getLine(), ".end sparse-switch".getBytes()) == 0
        || KMP.indexOf(cl.getLine(), ".end packed-switch".getBytes()) == 0) {
      isCurrentLineInSwitch = false;

      return true;
    }

    return false;
  }

  private List<BasicBlock> buildBlocks(List<Link> links, List<TryCatchBlock> tries, List<Integer> gotoLeaders) throws SmaliClassError {
    /* leaders = lines (or ints) which start a block, thus all targets of
       the links + first line + all targets of tries get the position of the leader codeline
       in this methods codeline array and put it into a treeset to sort all leaders.
     */
    TreeSet<Integer> leaders = new TreeSet<Integer>();
    // first line of the code is always a leader
    leaders.add(0);
    leaders.addAll(gotoLeaders);

    for (Link l : links) {
      CodeLine current = codeLines.getFirst();
      int index = 0;
      while (current.getLineNr() != l.getTo().getLineNr() && index < codeLines.size() - 1) {
        index++;
        current = codeLines.get(index);
      }

      if (index < codeLines.size()) {
        leaders.add(index);
      } else {
        throw new SmaliClassError("Could not link BasicBlocks in method: "
            + this.getName() + " from File: "
            + this.getSmaliClass().getFile().getAbsolutePath());
      }
    }

    for (TryCatchBlock t : tries) {
      CodeLine current = codeLines.getFirst();
      // special case which should never ever happen
      if (t.getBlockEnd() != null && t.getBlockEnd().getLineNr() == current.getLineNr())
        leaders.add(1);

      List<CodeLine> targets = t.getCatches();
      for (CodeLine c : targets) {
        int index = 0;
        while (current.getLineNr() != c.getLineNr() && index < codeLines.size() - 1) {
          index++;
          current = codeLines.get(index);
          if (t.getBlockEnd() != null && t.getBlockEnd().getLineNr() == current.getLineNr()
              && index < codeLines.size() - 1) {
            leaders.add(index + 1);
          }
        }

        if (index < codeLines.size()) {
          leaders.add(index);
        } else {
          throw new SmaliClassError("Could not link BasicBlocks in  method: "
              + this.getName() + " from File: "
              + this.getSmaliClass().getFile().getAbsolutePath());
        }
      }
    }

    // build all the blocks, based on the leaders
    // a block starts at a leader and extends until on line before the next leader

    // now that we know the leaders
    // start building + filling BBs

    LinkedList<BasicBlock> blocks = new LinkedList<>();
    List<CodeLine> returnList = new LinkedList<>();
    boolean hasThrow = false;
    boolean hasReturn = false;
    boolean hasGoto = false;

    Iterator<Integer> iter = leaders.iterator();
    Integer leader = iter.next();

    int nextLeader = -1;
    if (iter.hasNext())
      nextLeader = iter.next();

    // case if nextLeader == -1, just 1 block
    if (nextLeader == -1) {
      LinkedList<CodeLine> lines = new LinkedList<>();
      for (int i = leader; i < codeLines.size(); i++) {
        CodeLine c = codeLines.get(i);
        if (isSwitchStart(c))
          continue;
        if (isSwitchEnd(c))
          continue;
        if (isInSwitch())
          continue;

        if (c.getInstruction().getType() == InstructionType.GOTO) {
          hasGoto = true;
        }

        if (c.getInstruction().getType() == InstructionType.RETURN) {
          hasReturn = true;
          returnList.add(c);
        }

        if ((KMP.indexOf(c.getLine(), "throw".getBytes()) == 0)) {
          hasThrow = true;
        }

        lines.add(c);
      }

      BasicBlock block = new BasicBlock(lines, this);
      block.setHasReturn(hasReturn);
      block.setHasThrow(hasThrow);
      block.setHasGoto(hasGoto);

      if (block.hasReturn()) {
        try {
          CodeLine lastCodeLine = BasicBlock.getLastCodeLine(block).getCodeLine();

          if (returnList.size() > 1
              || (returnList.size() == 1 && lastCodeLine.getLineNr() != returnList.get(0).getLineNr())) {
            block.setHasDeadCode(true);
          }
        } catch (SyntaxException e) {
          LOGGER.error("Could not find last codeline, while searching for return codes.");
        }
      }

      returnList.clear();

      hasReturn = false;
      hasThrow = false;
      hasGoto = false;

      blocks.add(block);

    } else {
      // add first block
      LinkedList<CodeLine> lines = new LinkedList<CodeLine>();
      boolean justDotComment = true;

      for (int i = leader; i < nextLeader; i++) {
        CodeLine c = codeLines.get(i);

        if (c.isCode()) {
          justDotComment = false;
        }
        if (isSwitchStart(c))
          continue;
        if (isSwitchEnd(c))
          continue;
        if (isInSwitch())
          continue;
        if (c.getInstruction().getType() == InstructionType.GOTO) {
          hasGoto = true;
        }
        if (c.getInstruction().getType() == InstructionType.RETURN) {
          hasReturn = true;
          returnList.add(c);
        }
        if ((KMP.indexOf(c.getLine(), "throw".getBytes()) == 0)) {
          hasThrow = true;
        }

        lines.add(c);
      }

      if (!justDotComment) {
        BasicBlock block = new BasicBlock(lines, this);
        block.setHasReturn(hasReturn);
        block.setHasThrow(hasThrow);
        block.setHasGoto(hasGoto);

        if (block.hasReturn()) {
          try {
            CodeLine lastCodeLine = BasicBlock.getLastCodeLine(block).getCodeLine();

            if (returnList.size() > 1
                || (returnList.size() == 1 && lastCodeLine.getLineNr() != returnList.get(0).getLineNr())) {
              block.setHasDeadCode(true);
            }
          } catch (SyntaxException e) {
            LOGGER.error("Could not find last codeline, while searching for return codes.");
          }
        }

        returnList.clear();

        hasReturn = false;
        hasThrow = false;
        hasGoto = false;

        blocks.add(block);
      }

      // add all intermediate blocks
      while (iter.hasNext()) {
        if (!justDotComment)
          lines = new LinkedList<CodeLine>();

        justDotComment = true;

        // this while is used to merge blocks, which just consist of dot
        // comments with the next block
        while (justDotComment && iter.hasNext()) {
          leader = nextLeader;
          nextLeader = iter.next();

          for (int i = leader; i < nextLeader; i++) {
            CodeLine c = codeLines.get(i);

            if (c.isCode()) {
              justDotComment = false;
            }
            if (isSwitchStart(c))
              continue;
            if (isSwitchEnd(c))
              continue;
            if (isInSwitch())
              continue;
            if (c.getInstruction().getType() == InstructionType.GOTO) {
              hasGoto = true;
            }
            if (c.getInstruction().getType() == InstructionType.RETURN) {
              hasReturn = true;
              returnList.add(c);
            }
            if ((KMP.indexOf(c.getLine(), "throw".getBytes()) == 0)) {
              hasThrow = true;
            }

            lines.add(c);
          }
        }

        // just add the block if the while stopped because of no more dot comment
        // if it stopped because there is no following block, the code handling the last block
        // will add all this code aswell, because all the previous code was just .comment
        if (!justDotComment) {
          BasicBlock block = new BasicBlock(lines, this);
          block.setHasReturn(hasReturn);
          block.setHasThrow(hasThrow);
          block.setHasGoto(hasGoto);

          if (block.hasReturn()) {
            try {
              CodeLine lastCodeLine = BasicBlock.getLastCodeLine(block).getCodeLine();

              if (returnList.size() > 1
                  || (returnList.size() == 1 && lastCodeLine.getLineNr() != returnList.get(0).getLineNr())) {
                block.setHasDeadCode(true);
              }
            } catch (SyntaxException e) {
              LOGGER.error("Could not find last codeline, while searching for return codes.");
            }
          }

          returnList.clear();

          hasReturn = false;
          hasThrow = false;
          hasGoto = false;

          blocks.add(block);
        }
      }

      // add last block
      leader = nextLeader; // System.out.println("lastBlock");
      // just reset if we left the intermediate part by adding a block
      // and not when we still have "buffered" codelines in the list, because of .comment merging

      if (!justDotComment)
        lines = new LinkedList<CodeLine>();

      justDotComment = true;

      for (int i = leader; i < codeLines.size(); i++) {
        CodeLine c = codeLines.get(i);

        if (isSwitchStart(c)) {
          continue;
        }
        if (isSwitchEnd(c)) {
          continue;
        }
        if (isInSwitch()) {
          continue;
        }
        if (c.getInstruction().getType() == InstructionType.GOTO) {
          hasGoto = true;
        }
        if (c.getInstruction().getType() == InstructionType.RETURN) {
          hasReturn = true;
          returnList.add(c);
        }
        if ((KMP.indexOf(c.getLine(), "throw".getBytes()) == 0)) {
          hasThrow = true;
        }

        if (c.isCode()) {
          justDotComment = false;
        }

        lines.add(c);
      }

      if (!justDotComment) {
        BasicBlock block = new BasicBlock(lines, this);
        block.setHasReturn(hasReturn);
        block.setHasThrow(hasThrow);
        block.setHasGoto(hasGoto);

        if (block.hasReturn()) {
          try {
            CodeLine lastCodeLine = BasicBlock.getLastCodeLine(block).getCodeLine();

            if (returnList.size() > 1
                || (returnList.size() == 1 && lastCodeLine.getLineNr() != returnList.get(0).getLineNr())) {
              block.setHasDeadCode(true);
            }
          } catch (SyntaxException e) {
            LOGGER.error("Could not find last codeline, while searching for return codes.");
          }
        }

        returnList.clear();

        hasReturn = false;
        hasThrow = false;
        hasGoto = false;

        blocks.add(block);
      } else {
        LinkedList<CodeLine> linesPreviousBlock = blocks.getLast().getCodeLines();
        linesPreviousBlock.addAll(lines);
        BasicBlock block = new BasicBlock(linesPreviousBlock, this);
        blocks.removeLast();
        blocks.add(block);
      }
    }

    return blocks;
  }

  private List<BasicBlock> linkNew(List<BasicBlock> blocks, List<Link> links, List<TryCatchBlock> tries) {
    // first add all links
    for (Link l : links) {
      for (BasicBlock start : blocks) {
        if (/*!start.hasReturn() && !start.hasThrow() &&*/ //added for return in block followed by a goto, which is most likely patched into the code
            !start.getCodeLines().isEmpty()
            && start.getCodeLines().getLast().getLineNr()
            >= (l.getFrom().getLineNr())
            && start.getCodeLines().getFirst().getLineNr()
            <= (l.getFrom().getLineNr())
           ) {
          for (BasicBlock target : blocks) {
            // could also be done via line number
            if (!target.getCodeLines().isEmpty()
                && target.getCodeLines().getFirst().getLineNr()
                <= (l.getTo().getLineNr())
                && target.getCodeLines().getLast().getLineNr()
                >= (l.getTo().getLineNr())
               ) {
              //linkBBs(start, target);
              start.addNextBB(target);
              target.addPreviousBB(start);
              break;
            }
          }
          break;
        }
      }
    }

    // add all try code
    for (TryCatchBlock t : tries){
      for (BasicBlock start : blocks) {
        // found a block within the try
        if(!start.getCodeLines().isEmpty() &&
            start.getCodeLines().getLast().getLineNr() >= t.getBegin() &&
            start.getCodeLines().getLast().getLineNr() <= t.getEnd()) {

          // for every block, check if it is one of the catches
          for (CodeLine c : t.getCatches()) {
            // check all catches
            for (BasicBlock target : blocks) {
              if (!target.getCodeLines().isEmpty() &&
                   target.getCodeLines().getFirst().getLineNr() <= c.getLineNr() &&
                   target.getCodeLines().getLast().getLineNr() >= c.getLineNr()) {

                //linkBBs(start, target);

                start.addNextBB(target);
                target.addPreviousBB(start);
                start.setIsTryBlock(true);
                target.setIsCatchBlock(true);

                break;
              }
            }
          }
        }
      }
    }

    // link all the default cases
    // there is always a fall through, except for 3 cases: goto, return, throw
    Iterator<BasicBlock> iter = blocks.iterator();
    BasicBlock first = null;
    BasicBlock next;

    if (iter.hasNext())
      first = iter.next();

    while (iter.hasNext()) {
      next = iter.next();

      try {
        CodeLine lastLine = BasicBlock.getLastCodeLine(first).getCodeLine();

        // !(hasReturn() && !hasDeadCode()) && !(hasth)
        if (/*!first.hasDeadCode() && */!first.hasGoto() && lastLine.getInstruction().getType() != InstructionType.RETURN
            && !(KMP.indexOf(lastLine.getLine(), "throw".getBytes()) == 0)/*&& !first.hasReturn() &&! first.hasThrow()*/){
          //linkBBs(first, next);
          first.addNextBB(next);
          next.addPreviousBB(first);
        }
        first = next;
      } catch (SyntaxException e) {
        // this just happens if there is no code in the BB, so error is no error...
        // it can happen if there is a BB just consisting of a single label,
        // so link the BB to the next and previous on
        //linkBBs(first, next);
        first.addNextBB(next);
        next.addPreviousBB(first);

        first = next;
      }
    }

    return blocks;
  }

  public boolean isProbablyPatched() {
    if (hasUnlinkedBBs) {
      return true;
    } else {
      for (BasicBlock bb : getBasicBlocks()) {
        if (bb.hasDeadCode())
          return true;
      }
    }

    return false;
  }

  @Override
  public int compareTo(Method other) {
    return ComparisonChain.start()
        .compare(this.label, other.label)
        .compare(this.smaliClass.getFullClassName(true), other.smaliClass.getFullClassName(true))
        .result();
  }

  @Override
  public int hashCode() {
    return Objects.hash(smaliClass, label, methodType.toString(), name) +
        Arrays.hashCode(rawParameters) + Arrays.hashCode(returnValue);
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj)
      return true;

    if (obj == null || getClass() != obj.getClass())
      return false;

    final Method other = (Method) obj;

    return Objects.equals(this.smaliClass, other.smaliClass)
        && Objects.equals(this.label, other.label)
        && Objects.equals(this.methodType.toString(), other.methodType.toString())
        && Objects.equals(this.name, other.name)
        && Arrays.equals(this.rawParameters, other.rawParameters)
        && Arrays.equals(this.returnValue, other.returnValue);
  }

  @Override
  public String toString(){
    return name + "(" + getParameterString() + ")" + getReturnValueString();
  }

  /**
   * @return the SMALI file this method belongs to.
   */
  public SmaliClass getSmaliClass() {
    return smaliClass;
  }

  /**
   * Get the unique label of this Method within a SmaliClass.
   *
   * @return
   */
  public int getLabel() {
    return label;
  }

  public String getName() {
    return name;
  }

  public boolean hasUnlinkedBBs() {
    return hasUnlinkedBBs;
  }

  public void setHasUnlinkedBlocks(boolean hasUnlinkedBBs) {
    this.hasUnlinkedBBs = hasUnlinkedBBs;
  }

  public List<BasicBlock> getBasicBlocks() {
    return bbList;
  }

  public LinkedList<CodeLine> getCodeLines() {
    return codeLines;
  }

  /**
   * Does this method contain anything else besides an empty declaration?
   *
   * @return true if the method is "empty", false otherwise
   */
  public boolean isEmpty() {
    return bbList.isEmpty();
  }

  /**
   * Get the first BB.
   *
   * @return the first BB or null if none is available
   */
  public BasicBlock getFirstBasicBlock() {
    if (bbList.isEmpty())
      return null;

    return bbList.get(0); // firstBasicBlock;
  }

  /**
   * Return the class with full path, the method name and the (raw) parameters
   * as byte arrays.
   *
   * @return [ classname, name, parameters ]
   */
  public byte[][] getCmp() {
    byte[][] cmp = new byte[3][];
    cmp[0] = getSmaliClass().getFullClassName(false).getBytes();
    cmp[1] = name.getBytes();
    cmp[2] = rawParameters;

    return cmp;
  }

  /**
   * This gives the parameters in their short form.
   * see: https://code.google.com/p/smali/wiki/TypesMethodsAndFields for more information
   * @return the parameters of this method in their short letter form
   */
  public String getParameterString(){
    if (parameters == null) {
      parameters = new String(this.getParameters());
    }

    return parameters;
  }

  public String getReturnValueString() {
    if (returnValueString == null) {
      returnValueString = new String(returnValue);
      returnValueString = returnValueString.replaceAll("L.[^;]*;", "L");
    }

    return returnValueString;
  }

  /**
   * TODO and FIXME: convert the .method... line to a more java syntax, such
   * as private void full-class-name.methodname(String s); Right now this
   * method will only return the classpath and the .method name. It would be
   * best to overwrite this method which will append the full-class-name and
   * one method which does not do it (real java syntax)
   *
   * @return
   */
  public String getReadableJavaName() {
    return getSmaliClass().getFullClassName(true) + ": " +
        new String(getCodeLines().getFirst().getLine()).replace(".method", "").trim();
  }

  /**
   * Get the unparsed parameters of this method. .method public constructor
   * <init>(Landroid/content/Context;)V would return Landroid/content/Context;
   *
   * @return the parameter declaration
   */
  public byte[] getParameters() {
    return rawParameters;
  }

  public boolean isStatic() {
    return isStatic;
  }

  public boolean isNative() { return isNative; }

  public boolean isPrivate() {
    return isPrivate;
  }

  /**
   * Get the unparsed return value of this method. .method public constructor
   * <init>(Landroid/content/Context;)V would return V.
   *
   * @return the return value
   */
  public byte[] getReturnValue() {
    return returnValue;
  }

  public boolean returnsOnlyVoid() {
    if (!new String(returnValue).equals("V")) {
      return false;
    }

    try {
      CodeLine cl = BasicBlock.getFirstCodeLine(getFirstBasicBlock()).getCodeLine();
      if (cl.getInstruction().getType() == InstructionType.RETURN) {
        return true;
      }
    } catch (SyntaxException e) {
      LOGGER.error(e.getMessage());
    }

    return false;
  }

  public boolean returnsOnlyBoolean() {
    if (!new String(returnValue).equals("Z")) {
      return false;
    }

    try {
      BasicBlock.FoundCodeLine cl1 = BasicBlock.getFirstCodeLine(getFirstBasicBlock());
      BasicBlock.FoundCodeLine cl2 = BasicBlock.getNextCodeLine(getFirstBasicBlock(), cl1.getIndex());

      if (cl2.getCodeLine().getInstruction().getType() == InstructionType.RETURN) {
        return true;
      }
    } catch (SyntaxException e) {
      LOGGER.error(e.getMessage());
    }

    return false;
  }
}
