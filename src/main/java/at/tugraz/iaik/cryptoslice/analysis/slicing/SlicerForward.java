package at.tugraz.iaik.cryptoslice.analysis.slicing;

import at.tugraz.iaik.cryptoslice.application.*;
import at.tugraz.iaik.cryptoslice.application.instructions.Constant;
import at.tugraz.iaik.cryptoslice.application.instructions.Instruction;
import at.tugraz.iaik.cryptoslice.application.instructions.InstructionType;
import at.tugraz.iaik.cryptoslice.application.methods.BasicBlock;
import at.tugraz.iaik.cryptoslice.application.methods.Method;
import at.tugraz.iaik.cryptoslice.utils.ByteUtils;
import at.tugraz.iaik.cryptoslice.utils.FileList;
import at.tugraz.iaik.cryptoslice.utils.config.ConfigHandler;
import at.tugraz.iaik.cryptoslice.utils.config.ConfigKeys;
import com.google.common.primitives.Bytes;

import java.io.File;
import java.util.*;

public class SlicerForward extends Slicer {
  public SlicerForward(Application app, List<CodeLine> searchIds) {
    super(app, searchIds);
  }

  // For now, only constants are searchable.
  @Override
  public void startSearch(SlicingCriterion criterion) throws DetectionLogicError {
    this.criterion = criterion;

    SlicingPatternFT pattern = (SlicingPatternFT) criterion.getPattern();
    if (pattern.getType().equals("OBJECT")) {
      this.cmp[0] = pattern.getQualifiedClassName().getBytes();
      this.cmp[1] = pattern.getMethodName().getBytes();
      this.cmp[2] = null;

      List<TodoList.RegisterSearch> rsList = findObjectInvokes(cmp);
      LOGGER.debug("Found {} INVOKES for {}.{}", rsList.size(), new String(cmp[0]), new String(cmp[1]));

      for (TodoList.RegisterSearch rs : rsList) {
        currentSliceTree = new SliceTree();
        todoList = new TodoList(this);
        todoList.addRegisterToTrack(rs);

      /*
       * Set up searchid. Each Codeline where a search begins gets the same id.
       * This is useful to match Constants which are found for the same
       * invocation but for different arguments.
       */
        CodeLine cl = rs.getBB().getCodeLines().get(rs.getIndex()+1);
        searchId = searchIds.indexOf(cl);
        if (searchId == -1) {
          searchIds.add(cl);
          searchId = searchIds.size() - 1;
        }

        startTracking();

        if (!currentSliceTree.getSliceNodes().isEmpty())
          this.criterion.addToSliceTress(searchId, currentSliceTree);
      }
    } else {
      if (pattern.getConstantId().isEmpty()) {
        LOGGER.debug("No constantId found for resourceId {}. Aborting", pattern.getSearchPattern());
        return;
      }

      /*
       * Get a list of all invokes and start a search for each one. Each search gets a unique searchId which is assigned to all
       * constants which are found for the corresponding register/invoke.
       */
      LinkedList<TodoList.RegisterSearch> rsList = findConstantId(pattern.getConstantId());
      if (rsList.isEmpty()) // nothing found for the constantId? Search the pattern itself!
        rsList = findConstantId("\"" + pattern.getSearchPattern() + "\""); // i.e. const-string v0, "@id/password"
      Map<CodeLine, byte[][]> fieldMap = findFieldId(pattern.getConstantId());
      LOGGER.debug("Found {} constant assignments, {} field assignments.", rsList.size(), fieldMap.size());

      for (TodoList.RegisterSearch rs : rsList) {
        currentSliceTree = new SliceTree();
        todoList = new TodoList(this);

        SliceNode sliceNode = currentSliceTree.addNode(rs);
        rs.setPreviousSliceNode(sliceNode);
        todoList.addRegisterToTrack(rs);

        /*
         * Set up searchid. Each Codeline where a search begins gets the same id.
         * This is useful to match Constants which are found for the same invocation but for different arguments.
         */
        CodeLine cl = rs.getBB().getCodeLines().get(rs.getIndex());
        searchId = searchIds.indexOf(cl);
        if (searchId == -1) {
          searchIds.add(cl);
          searchId = searchIds.size() - 1;
        }

        startTracking();
        if (!currentSliceTree.getSliceNodes().isEmpty())
          this.criterion.addToSliceTress(searchId, currentSliceTree);
      }

      for (Map.Entry<CodeLine, byte[][]> field : fieldMap.entrySet()) {
        currentSliceTree = new SliceTree();
        todoList = new TodoList(this);

        todoList.addField(field.getValue(), 0, 0, new LinkedList<BasicBlock>(), null, null);

        searchId = searchIds.indexOf(field.getKey());
        if (searchId == -1) {
          searchIds.add(field.getKey());
          searchId = searchIds.size() - 1;
        }

        startTracking();

        if (!currentSliceTree.getSliceNodes().isEmpty())
          this.criterion.addToSliceTress(searchId, currentSliceTree);
      }
    }
  }

  @Override
  protected void startTracking() throws DetectionLogicError {
    LOGGER.debug("Starting search...");

    int loopCnt = 0;
    while (!todoList.isFinished()) {
      // Sanity check ;)
      loopCnt++;
      if (loopCnt == MAX_ITERATIONS)
        throw new DetectionLogicError("We're probably stuck in an endless loop while working through the TODO list. Aborting!");

      if (todoList.getFinishedRsCount() > TodoList.MAX_RS_COUNT)
        throw new DetectionLogicError("Reached maximum RS limit (" + TodoList.MAX_RS_COUNT + ")");

      try {
        TodoList.RegisterSearch rs = todoList.getNextRegisterToTrack();
        if (rs != null) {
          forwardTrackRegister(rs);
        } else if (todoList.hasRemainingFieldsToTrack()) {
          TodoList.ClassContentTracker ctt = todoList.getNextField();
          forwardTrackField(ctt);
        }
      } catch (SyntaxException e) {
        LOGGER.error("Syntax Error (Search continues)", e);
        criterion.logException(e);
      } catch (DetectionLogicError e) {
        LOGGER.error("Logic Error (Search continues)", e);
        criterion.logException(e);
      }
    }

    LOGGER.debug("Search finished.");
  }

  private void forwardTrackRegister(final TodoList.RegisterSearch rs) throws SyntaxException, DetectionLogicError {
    byte[] register = rs.getRegister();
    BasicBlock bb = rs.getBB();
    int actualLine = rs.getIndex();

    LOGGER.debug("forwardTrackRegister: reg={}, actualLine={}", new String(register),
        rs.getBB().getCodeLines().get(rs.getIndexAbsolute()).getLineNr());

		/*
		 * Safeguards:
		 * - In TodoList: If the fuzzy level is too high, skip the request as the results would get too bloated.
		 * - Here: If the method is not static and p0 is tracked, abort tracking. p0 is the this-reference and
		 * this will most likely mess things up, as every called method on the corresponding class etc would be tracked.
		 */
    if (!bb.getMethod().isStatic() && Arrays.equals(P0_THIS, register)) {
      LOGGER.debug("forwardTrackRegister: Will not track p0 in non-static method ({})", bb.getMethod().getName());
      return;
    }

    final LinkedList<BasicBlock> path = rs.getPath();
    if (path.isEmpty() || !(path.getLast() == bb)) {
      // add the current BB to the path but no duplicates (at the end)
      path.addLast(bb);
    }

    // Get the current sliceNode object
    SliceNode sliceNode = rs.getPreviousSliceNode();

		/*
		 * Check all opcodes in the BB.
		 * actualLine points to the CodeLine which was found in the previous search.
		 * The next opcode of interest is any previous opcode which relates to the tracked register.
		 * A procedure after this while loop handles the case when the beginning of a BB is reached.
		 */
    while (actualLine < bb.getCodeLines().size()-1) { // look at all code lines in this BB
      CodeLine cl = bb.getCodeLines().get(++actualLine); // look at the next instruction
      if (!cl.isCode()) continue; // skip all non-code lines

      Instruction i = cl.getInstruction(); // get the instruction and work with it
      LOGGER.trace("forwardTrackRegister: Checking codeline {}", cl);

      switch (i.getType()) {
        case AGET:
          if (Arrays.equals(i.getInvolvedRegisters().get(0), register) || // array
              Arrays.equals(i.getInvolvedRegisters().get(1), register)) { // array index

            // Track the requested array element with elevated fuzzy level because the value is non-concrete.
            TodoList.RegisterSearch rsAgetReg = new TodoList.RegisterSearch(i.getResultRegister(), rs.getFieldInRegister(), bb,
                actualLine, rs.getFuzzyLevel()+1, rs.getFuzzyOffset(), new LinkedList<BasicBlock>(path), sliceNode, rs.getPreviousRegister());
            sliceNode = currentSliceTree.addNode(rsAgetReg);
            rsAgetReg.setPreviousSliceNode(sliceNode);
            todoList.addRegisterToTrack(rsAgetReg);

            // Track the array further.
            TodoList.RegisterSearch rsAgetArray = new TodoList.RegisterSearch(register, rs.getFieldInRegister(), bb, actualLine,
                rs.getFuzzyLevel(), rs.getFuzzyOffset(), new LinkedList<BasicBlock>(path), sliceNode, rs.getPreviousRegister());
            todoList.addRegisterToTrack(rsAgetArray);

            return;
          } else if (Arrays.equals(i.getResultRegister(), register)) {
            LOGGER.debug("forwardTrackRegister: Lost track (AGET). The register is overwritten.");
            return;
          }

          continue;

        case APUT:
          if (Arrays.equals(i.getInvolvedRegisters().get(0), register)) { // array element
            // Track the currently tracked register further.
            TodoList.RegisterSearch rsAputReg = new TodoList.RegisterSearch(register, rs.getFieldInRegister(), bb, actualLine,
                rs.getFuzzyLevel(), rs.getFuzzyOffset(), new LinkedList<BasicBlock>(path), sliceNode, rs.getPreviousRegister());
            sliceNode = currentSliceTree.addNode(rsAputReg);
            rsAputReg.setPreviousSliceNode(sliceNode);
            todoList.addRegisterToTrack(rsAputReg);

            // Also track the array now.
            TodoList.RegisterSearch rsAputArray = new TodoList.RegisterSearch(i.getResultRegister(), rs.getFieldInRegister(), bb, actualLine,
                rs.getFuzzyLevel(), rs.getFuzzyOffset(), new LinkedList<BasicBlock>(path), sliceNode, i.getResultRegister());
            todoList.addRegisterToTrack(rsAputArray);

            return;
          }

          /* Note:
           * a) If the tracked 'register' is the index of an entry that should be added to the array:
           * -> considered very unlikely to happen.
           * b) When tracking the array, an APUT occurs:
           * -> do nothing because the tracked 'register' (array) does not influence the array entry.
           */

          continue;

        case CONST: // The tracked register is overwritten - track lost
        case FILL_ARRAY_DATA:
        case INTERNAL_SMALI_OPCODE:
        case NEW_INSTANCE:
          if (Arrays.equals(i.getResultRegister(), register)) {
            LOGGER.debug("forwardTrackRegister: Lost track. The register is overwritten.");
            return;
          }
          continue;

        case FILLED_NEW_ARRAY:
          // Check if our register is involved in this opcode.
          boolean foundReg = false;
          for (byte[] involvedReg : i.getInvolvedRegisters()) {
            if (Arrays.equals(register, involvedReg)) {
              foundReg = true;
              break;
            }
          }

          BasicBlock.FoundCodeLine fcl = BasicBlock.getNextOpcode(bb, cl); // look for a subsequent MOVE_RESULT
          Instruction ii = fcl.getCodeLine().getInstruction();
          boolean resultWasMoved = (ii.getType() == InstructionType.MOVE_RESULT);

          if (foundReg) {
            // Starting from the current FILLED_NEW_ARRAY line, track the register further
            TodoList.RegisterSearch rs1 = new TodoList.RegisterSearch(register, rs.getFieldInRegister(), bb, actualLine,
                rs.getFuzzyLevel(), rs.getFuzzyOffset(), new LinkedList<BasicBlock>(path), sliceNode, rs.getPreviousRegister());
            sliceNode = currentSliceTree.addNode(rs1);
            rs1.setPreviousSliceNode(sliceNode);
            rs1.setPreviousRegister(register); // rs.getPreviousRegister() above was only for the graph output.
            todoList.addRegisterToTrack(rs1);

            // Process a subsequent MOVE_RESULT line
            if (resultWasMoved && !Arrays.equals(ii.getResultRegister(), register)) {
              /*
               * Actually previousRegister register would be ii.getResultRegister() instead of register.
               * However, as we do not display MOVE_RESULT lines, register is taken for a consistent output.
                */
              TodoList.RegisterSearch rs2 = new TodoList.RegisterSearch(ii.getResultRegister(), rs.getFieldInRegister(),
                  fcl.getBasicBlock(), fcl.getIndex(), rs.getFuzzyLevel()+1, rs.getFuzzyOffset(),
                  new LinkedList<BasicBlock>(path), sliceNode, register);
              todoList.addRegisterToTrack(rs2);
            }
            return;
          } else if (resultWasMoved && Arrays.equals(ii.getResultRegister(), register)) {
            // Abort here because MOVE_RESULT of a previous FILLED_NEW_ARRAY opcode, overwrites the tracked register.
            LOGGER.debug("forwardTrackRegister: Lost track (move-result). The register is overwritten.");
            return;
          }

          continue;

        case GET: // Some field is loaded into our register
          byte[][] getResField = Instruction.parseClassAndField(i.getInvolvedFields().get(0));
          if (rs.getFieldInRegister() != null &&
              Arrays.equals(rs.getFieldInRegister()[0], getResField[0]) &&
              Arrays.equals(rs.getFieldInRegister()[1], getResField[1])) {
            // Register is actually not overwritten because the field is the same.
            continue;
          } else if (Arrays.equals(i.getResultRegister(), register)) {
            // Abort here because the tracked register is overwritten by the return value of some GET operation.
            LOGGER.debug("forwardTrackRegister: Lost track (get). The register is overwritten.");
            return;
          }

          /* Note: When the tracked 'register' corresponds to i.getInvolvedFields().get(1) (which works for iget only),
           * we do nothing here because 'register' is not actually influenced.
           */

          continue;

        case GOTO:
        case IGNORE:
        case NOP:
          continue;

        case INVOKE_STATIC:
        case INVOKE:
          // TODO: do we actually need this? here cmp is null at the begin (depending on the pattern)
          // would just mean that we could also start tracking at an invoke statement
          // Check if this invoke involves our currently searched method, if so, we do not need to investigate anything else
          /*if (Arrays.equals(i.getCalledClassAndMethodWithParameter()[0], cmp[0])
              && Arrays.equals(i.getCalledClassAndMethodWithParameter()[1], cmp[1])
              && (cmp[2] == null || Arrays.equals(i.getCalledClassAndMethodWithParameter()[2], cmp[2])
          )) {
            continue;
          }*/

          // Check if our register is involved in this opcode.
          boolean foundInvReg = false;
          for (byte[] involvedReg : i.getInvolvedRegisters()) {
            if (Arrays.equals(register, involvedReg)) {
              foundInvReg = true;
              break;
            }
          }

          fcl = BasicBlock.getNextOpcode(bb, cl); // look for a subsequent MOVE_RESULT
          ii = fcl.getCodeLine().getInstruction();
          resultWasMoved = (ii.getType() == InstructionType.MOVE_RESULT);

          if (foundInvReg) {
            /*
             * We now track all return values from this method. In order not to track too many constants
             * which might be unrelated, we set a large offset to the fuzzy value. This way, the fuzzy
             * value in the results will be "normal", but if the fuzzyValue+offset gets too large, further
             * searches will be cancelled. Since we do not know what happens in the methods, we do not
             * want to track into methods which call the found method and so on. We therefore set
             * the offset to the maximum-3.
             */
            int fuzzyLevelOffset = rs.getFuzzyLevel();
            if (fuzzyLevelOffset < TodoList.MAX_FUZZY_LEVEL-3)
              fuzzyLevelOffset = TodoList.MAX_FUZZY_LEVEL-3;

            // Starting from the current INVOKE line, track the register further
            TodoList.RegisterSearch rs1 = new TodoList.RegisterSearch(register, rs.getFieldInRegister(), bb, actualLine,
                rs.getFuzzyLevel(), fuzzyLevelOffset, new LinkedList<BasicBlock>(path), sliceNode, rs.getPreviousRegister());
            sliceNode = currentSliceTree.addNode(rs1);
            rs1.setPreviousSliceNode(sliceNode);
            rs1.setPreviousRegister(register); // rs.getPreviousRegister() above was only for the graph output.
            todoList.addRegisterToTrack(rs1);

            /*
             * handleInvokeForward is intentionally done after adding the sliceNode above.
             * Thus, we can slice further, based on the current sliceNode.
             */
            boolean isMethodKnown = handleInvokeForward(bb, actualLine, register, resultWasMoved, rs.getFuzzyLevel(),
                fuzzyLevelOffset, new LinkedList<BasicBlock>(path), sliceNode);

            // Also track the object instance if different from the currently tracked register
            int fuzzyLevelInvoke = (isMethodKnown) ? rs.getFuzzyLevel() : rs.getFuzzyLevel() + 1;
            if (i.getType() != InstructionType.INVOKE_STATIC && // only virtual invokes
                !Arrays.equals(i.getInvolvedRegisters().get(0), P0_THIS) && // evade overtracking by not tracking p0
                !Arrays.equals(i.getInvolvedRegisters().get(0), register) && // already tracked above
                // if registers equal, track it below at MOVE_RESULT
                !(resultWasMoved && Arrays.equals(i.getInvolvedRegisters().get(0), ii.getResultRegister()))) {

              // Check if this register is deduced from a field
              byte[][] resultField = rs.getFieldInRegister();
              for (int j = actualLine; j >= 0; j--) { // check all codelines in the current BB (only!)
                CodeLine clj = bb.getCodeLines().get(j);
                Instruction instructionj = clj.getInstruction();
                byte[] targetRegj = instructionj.getResultRegister();

                if ((instructionj.getType() == InstructionType.GET) && Arrays.equals(i.getInvolvedRegisters().get(0), targetRegj)) {
                  // We found a GET and it copies into our register

                  resultField = Instruction.parseClassAndField(instructionj.getInvolvedFields().get(0));
                  LOGGER.trace("forwardTrackRegister: Register originates from field {}->{} (cl={})",
                      new String(resultField[0]), new String(resultField[1]), clj.getLineNr());
                  break;
                }
                else if (Arrays.equals(i.getInvolvedRegisters().get(0), targetRegj)) { // overwritten
                  break;
                }
              }

              // Based on the current INVOKE (previously set sliceNode), trace the object instance register further
              TodoList.RegisterSearch rs2 = new TodoList.RegisterSearch(i.getInvolvedRegisters().get(0), resultField, bb,
                  actualLine, fuzzyLevelInvoke, fuzzyLevelOffset, new LinkedList<BasicBlock>(path), sliceNode,
                  i.getInvolvedRegisters().get(0));
              todoList.addRegisterToTrack(rs2);
            }

            // Process a possibly subsequent MOVE_RESULT line
            if (resultWasMoved && !Arrays.equals(ii.getResultRegister(), register)) {
              /*
               * Actually previousRegister register would be ii.getResultRegister() instead of register.
               * However, as we do not display MOVE_RESULT lines, register is taken for a consistent output.
                */
              TodoList.RegisterSearch rs3 = new TodoList.RegisterSearch(ii.getResultRegister(), rs.getFieldInRegister(),
                  fcl.getBasicBlock(), fcl.getIndex(), fuzzyLevelInvoke, fuzzyLevelOffset,
                  new LinkedList<BasicBlock>(path), sliceNode, register);
              todoList.addRegisterToTrack(rs3);
            }
            return;
          }  else if (resultWasMoved && Arrays.equals(ii.getResultRegister(), register)) {
            // Abort here because MOVE_RESULT of a previous INVOKE opcode, overwrites the tracked register.
            LOGGER.debug("forwardTrackRegister: Lost track (MOVE_RESULT). The register is overwritten.");
            return;
          }

          continue;

        case JMP:
          // JMPs have no influence on the slice. We use them to draw a structured output of subsequent BBs.
          if (ConfigHandler.getInstance().getBooleanConfigValue(ConfigKeys.ANALYSIS_SLICING_INCLUDE_JMP)) {
            TodoList.RegisterSearch rsJmp = new TodoList.RegisterSearch(register, rs.getFieldInRegister(), bb, actualLine,
                rs.getFuzzyLevel(), rs.getFuzzyOffset(), new LinkedList<BasicBlock>(path), sliceNode, rs.getPreviousRegister());
            sliceNode = currentSliceTree.addNode(rsJmp);
            // No, we intentionally do not add the register to the todoList here. No return here.
          } else {
            for (byte[] involvedReg : i.getInvolvedRegisters()) {
              if (Arrays.equals(register, involvedReg)) {
                TodoList.RegisterSearch rsJmp = new TodoList.RegisterSearch(register, rs.getFieldInRegister(), bb,actualLine,
                    rs.getFuzzyLevel(), rs.getFuzzyOffset(), new LinkedList<BasicBlock>(path), sliceNode, rs.getPreviousRegister());
                sliceNode = currentSliceTree.addNode(rsJmp);

                break;
              }
            }
          }

          continue;

        case MATH_1:  // Unary operations with only 1 target and 1 source reg
        case MATH_2C: // Binary operations with 1 target, 1 source and 1 constant (instead of register)
          if (Arrays.equals(i.getInvolvedRegisters().get(0), register)) {
            // dstReg might also be the same as register, i.e. add-int/lit8 v13, v13, 0x4
            byte[] dstReg = i.getResultRegister();

            TodoList.RegisterSearch rsMath = new TodoList.RegisterSearch(dstReg, rs.getFieldInRegister(), bb, actualLine,
                rs.getFuzzyLevel(), rs.getFuzzyOffset(), new LinkedList<BasicBlock>(path), sliceNode, register);
            sliceNode = currentSliceTree.addNode(rsMath);
            rsMath.setPreviousSliceNode(sliceNode);
            todoList.addRegisterToTrack(rsMath);
            return;
          } else if (Arrays.equals(i.getResultRegister(), register)) {
            // Consider the register overwritten only if it is not involved anyhow.
            LOGGER.debug("forwardTrackRegister: Lost track (MATH_1/2C). The register is overwritten.");
            return;
          }
          continue;

        case MATH_2: // Binary operations with 1 target and 2 sources
          if (Arrays.equals(i.getInvolvedRegisters().get(0), register) ||
              Arrays.equals(i.getInvolvedRegisters().get(1), register)) {

            // i.getResultRegister() might also be the same as register, i.e. add-float v13, v13, v2
            TodoList.RegisterSearch rsMath = new TodoList.RegisterSearch(i.getResultRegister(), rs.getFieldInRegister(), bb,
                actualLine, rs.getFuzzyLevel(), rs.getFuzzyOffset(), new LinkedList<BasicBlock>(path), sliceNode, register);
            sliceNode = currentSliceTree.addNode(rsMath);
            rsMath.setPreviousSliceNode(sliceNode);
            todoList.addRegisterToTrack(rsMath);

            return;
          } else if (Arrays.equals(i.getResultRegister(), register)) {
            // Consider the register overwritten only if it is not involved anyhow.
            LOGGER.debug("forwardTrackRegister: Lost track (MATH_2). The register is overwritten.");
            return;
          }
          continue;

        case MOVE: // Track the target register which got copied(!) from the source register.
          if (Arrays.equals(i.getInvolvedRegisters().get(0), register)) {
            /*
             * In practice, it can be observed that moved registers are accessed later.
             * So MOVE is actually copying the value from one register to another.
             *
             * Note that we could also omit adding this instruction to the graph.
             * However, nodes would seem wrongly linked and readers might assume the slice is wrong.
             * So we better add it and thereby avoid confusion.
             */
            /*RegisterSearch rsMove = new RegisterSearch(register, rs.getFieldInRegister(), bb, actualLine,
                rs.getFuzzyLevel(), rs.getFuzzyOffset(), new LinkedList<BasicBlock>(path), sliceNode, rs.getPreviousRegister());
            todoList.addRegisterToTrack(rsMove);
            register = i.getResultRegister();*/

            LOGGER.debug("forwardTrackRegister: MOVE - now tracking {} and {}",
                new String(register), new String(i.getResultRegister()));

            TodoList.RegisterSearch rsMove = new TodoList.RegisterSearch(register, rs.getFieldInRegister(), bb, actualLine,
                rs.getFuzzyLevel(), rs.getFuzzyOffset(), new LinkedList<BasicBlock>(path), sliceNode, rs.getPreviousRegister());
            sliceNode = currentSliceTree.addNode(rsMove);
            rsMove.setPreviousSliceNode(sliceNode);
            todoList.addRegisterToTrack(rsMove);

            // Track the target register where the value is moved to.
            rsMove = new TodoList.RegisterSearch(i.getResultRegister(), rs.getFieldInRegister(), bb, actualLine,
                rs.getFuzzyLevel(), rs.getFuzzyOffset(), new LinkedList<BasicBlock>(path), sliceNode, i.getResultRegister());
            todoList.addRegisterToTrack(rsMove);

            return;
          } else if (Arrays.equals(i.getResultRegister(), register)) {
            // Consider the register overwritten only if it is not involved somehow at all.
            LOGGER.debug("forwardTrackRegister: Lost track (MOVE). The register is overwritten.");
            return;
          }
          continue;

        case MOVE_RESULT: // Follows after FILLED_NEW_ARRAY and eventually after INVOKE. Handled there.
          continue;

        case NEW_ARRAY: // Track the array register further (generous slice -> fuzzylevel+1)
          if (Arrays.equals(i.getInvolvedRegisters().get(0), register)) {
            // I.e. tracking v13: new-array v5, v13 [= size register], [B
            TodoList.RegisterSearch rsNewArr = new TodoList.RegisterSearch(i.getResultRegister(), rs.getFieldInRegister(), bb, actualLine,
                rs.getFuzzyLevel()+1, rs.getFuzzyOffset(), new LinkedList<BasicBlock>(path), sliceNode, register);
            sliceNode = currentSliceTree.addNode(rsNewArr);
            rsNewArr.setPreviousSliceNode(sliceNode);
            todoList.addRegisterToTrack(rsNewArr);

            return;
          } else if (Arrays.equals(i.getResultRegister(), register)) {
            LOGGER.debug("forwardTrackRegister: Lost track (NEW_ARRAY). The register is overwritten.");
            return;
          }
          continue;

        case PUT:
          if (Arrays.equals(i.getInvolvedRegisters().get(0), register)) {
            LOGGER.debug("forwardTrackRegister: Found a PUT. Seems we are tracking a field assignment!");

            // Starting from the current PUT line, track the currently tracked register further.
            TodoList.RegisterSearch rs1 = new TodoList.RegisterSearch(register, rs.getFieldInRegister(), bb, actualLine,
                rs.getFuzzyLevel(), rs.getFuzzyOffset(), new LinkedList<BasicBlock>(path), sliceNode,
                rs.getPreviousRegister());
            sliceNode = currentSliceTree.addNode(rs1);
            rs1.setPreviousSliceNode(sliceNode);
            todoList.addRegisterToTrack(rs1);

            todoList.addField(i.getResultField(), rs.getFuzzyLevel(), rs.getFuzzyOffset(),
                new LinkedList<BasicBlock>(path), sliceNode, register);
            LOGGER.debug("forwardTrackRegister: Will later track cf={}.{}", new String(i.getResultField()[0]), new String(i.getResultField()[1]));

            return;
          }

          continue;

        case RETURN:
          /*
           * We could add the return line to the graph but this would result in a lot of overhead and
           * meaningless expressions, we omit this step.
           */

          /*
           * If we got to this RETURN while continuously tracking a field (= actually the field processing register),
           * and the register is returned now, we have to search for INVOKES of this method and subsequent
           * MOVE_RESULT lines. Thereby, we can track the register further.
           *
           * In fact, we do the same thing for ordinary registers at the INVOKE + MOVE_RESULT case.
           * There, we are more exact because due to the already known MOVE_RESULT we do not have to search for INVOKEs.
           */
          if (rs.getFieldInRegister() != null && !i.getInvolvedRegisters().isEmpty() &&
              Arrays.equals(i.getInvolvedRegisters().get(0), register)) {

            byte[][] method = bb.getMethod().getCmp();
            LOGGER.debug("Searching INVOKES with return value from method {}.{}", new String(method[0]), new String(method[1]));

            int foundInvokes = findReturnValuesFromInvoke(method, rs.getFuzzyLevel(), rs.getFuzzyOffset(),
                new LinkedList<BasicBlock>(path), sliceNode, register);
            LOGGER.debug("Found {} INVOKES of {}.{}", foundInvokes, new String(method[0]), new String(method[1]));
            /*
             * If the method is never invoked, it is likely called over java.lang.reflect or is some entry point from,
             * eg. the Android framework as android.content.BroadcastReceiver.onReceive(..) would be.
             */
          }

          return; // End a RegisterSearch here because after a RETURN, we are definitely done.

        default:
          LOGGER.debug("Did not handle opcode {}/{} (default)", i.getType(), new String(i.getOpCode()));
      }
    } // while end

    LinkedList<BasicBlock> nextBBs = bb.getNextBB();
    if (nextBBs != null && !nextBBs.isEmpty()) {
			/*
			 * Search for the register in all BBs "below" this one because we reached the end of the actual BB.
			 * Do this with a new RS object because that way we do not look into a BB more than once for the same register.
			 */
      LOGGER.debug("Reached end of BB, adding RS for all subsequent blocks.");

      for (BasicBlock bbb : nextBBs) {
        // index: -1 will let the search start at line 0
        TodoList.RegisterSearch rs2 = new TodoList.RegisterSearch(register, rs.getFieldInRegister(), bbb, -1,
            rs.getFuzzyLevel(), rs.getFuzzyOffset(), new LinkedList<BasicBlock>(path), sliceNode, register);
        // We add no sliceNode here because we do not have any yet.
        todoList.addRegisterToTrack(rs2);
      }
    }
  }

  private void forwardTrackField(TodoList.ClassContentTracker ctt) throws SyntaxException {
    byte[][] cf = ctt.getCi();
    LOGGER.debug("Forward tracking field {}.{}", new String(cf[0]), new String(cf[1]));

    File ff = new File(app.getSmaliDirectory(), new String(cf[0]) + FileList.SMALI_FILES);
    SmaliClass sf;
    if ((sf = app.getSmaliClass(ff)) == null) {
      LOGGER.debug("forwardTrackField: Lost track, class not available, file={}", ff.getAbsolutePath());
      return;
    }

    for (Field f : sf.getAllFields()) {
      LOGGER.trace("Checking field {} in {}", f.getFieldName(), sf.getFile().getName());

      if (f.getFieldName().equals(new String(cf[1]))) {
        LOGGER.trace(" ...it matches our pattern!");

				/*
				 * If the field is final, it will get its value assigned in the constructor (<init>).
				 * We could be smart and parse only the constructor, but we are lazy and search for
				 * all PUTs which use this field, see below.
				 *
				 * Additionally, if the field is only static and has a value set, a corresponding PUT
				 * is to be found in the static constructor (<clinit>).
				 *
				 * We will now search all IPUTs and SPUTs which operate on this field and put them as a
				 * RegisterSearch into the TodoList.
				 */
        for (SmaliClass sf2 : app.getAllSmaliClasses()) {
          for (Method m : sf2.getMethods()) {
            /*if (isFinalAndStatic && !Arrays.equals(Method.STATIC_CONSTRUCTOR_NAME, m.getName().getBytes()))
              continue; // we only need to look into <clinit>.*/

            for (BasicBlock bb : m.getBasicBlocks()) {
              for (int i = 0; i < bb.getCodeLines().size(); i++) { // look at all get opcodes in all BBs
                CodeLine cl = bb.getCodeLines().get(i);
                Instruction instr = cl.getInstruction();
                if (instr.getType() == InstructionType.GET) {
                  // check the classname and fieldname
                  byte[][] resultField = Instruction.parseClassAndField(instr.getInvolvedFields().get(0));

                  if (Arrays.equals(cf[0], resultField[0]) && Arrays.equals(cf[1], resultField[1])) {
                    // we have a GET opcode which puts into our field
                    LOGGER.debug("backTrackField:   Found a valid xGET in {}.{}(...), adding reg {} to TodoList, cl={}",
                        sf2.getFullClassName(true), m.getName(), new String(instr.getResultRegister()), cl);

                    LinkedList<BasicBlock> newPath = new LinkedList<BasicBlock>(ctt.getPath());
                    newPath.add(bb); // add the found BB to the path

                    TodoList.RegisterSearch rs = new TodoList.RegisterSearch(instr.getResultRegister(), resultField,
                        bb, i, ctt.getFuzzyLevel(), ctt.getFuzzyOffset(), newPath, ctt.getPreviousSliceNode(),
                        ctt.getPreviousRegister()); // there is only one register involved
                    SliceNode sliceNode = currentSliceTree.addNode(rs);
                    rs.setPreviousSliceNode(sliceNode);
                    rs.setPreviousRegister(instr.getResultRegister());
                    todoList.addRegisterToTrack(rs); // add this reg to our todolist in order to continue search later on*/
                  }
                }
              }
            }
          }
        }

        break; // because there might be only 1 field with a certain name in one file.
      }
      else {
        LOGGER.trace("Field does not match our search pattern!");
      }
    }
  }

  private int findReturnValuesFromInvoke(byte[][] cmp, int fuzzyLevel, int fuzzyLevelOffset,
                                         LinkedList<BasicBlock> path, SliceNode sliceNode,
                                         byte[] previousRegister) throws DetectionLogicError, SyntaxException {
    int invokeCount = 0;

    for (SmaliClass smaliClass : app.getAllSmaliClasses()) {
      for (Method m : smaliClass.getMethods()) {
        for (BasicBlock bb : m.getBasicBlocks()) {
          for (CodeLine cl : bb.getCodeLines()) {
            Instruction i = cl.getInstruction();

            // Search for the actual invoke instruction
            if (i.getType() == InstructionType.INVOKE || i.getType() == InstructionType.INVOKE_STATIC) {
              if (Arrays.equals(i.getCalledClassAndMethodWithParameter()[0], cmp[0]) &&
                  Arrays.equals(i.getCalledClassAndMethodWithParameter()[1], cmp[1]) &&
                  (cmp[2] == null || Arrays.equals(i.getCalledClassAndMethodWithParameter()[2], cmp[2]))) {
                // Found a method with correct invoke
                invokeCount++;

                LOGGER.debug("findReturnValuesFromInvoke: Method {}->{} invokes {}->{}({}) on line {}",
                    smaliClass.getFullClassName(true), m.getName(), new String(cmp[0]), new String(cmp[1]),
                    new String(i.getCalledClassAndMethodWithParameter()[2]), cl.getLineNr());

                // Look for a proximate MOVE_RESULT statement
                BasicBlock.FoundCodeLine fcl = BasicBlock.getNextOpcode(bb, cl);
                Instruction ii = fcl.getCodeLine().getInstruction();

                // Track the MOVE_RESULT register, starting at the INVOKE statement
                if (ii.getType() == InstructionType.MOVE_RESULT) {
                  int index = bb.getCodeLines().indexOf(cl);

                  TodoList.RegisterSearch rs = new TodoList.RegisterSearch(ii.getResultRegister(), bb, index,
                      fuzzyLevel, fuzzyLevelOffset, path, sliceNode, previousRegister);
                  SliceNode sliceNodeNew = currentSliceTree.addNode(rs);
                  rs.setPreviousSliceNode(sliceNodeNew);
                  rs.setPreviousRegister(ii.getResultRegister()); // previousRegister above was only for the graph.
                  todoList.addRegisterToTrack(rs);
                } // else: No subsequent MOVE_RESULT -> lost track!
              }
              //else: Invoke did not match.
            }
          }
        }
      }
    }

    return invokeCount;
  }

  private boolean handleInvokeForward(BasicBlock bb, int index, byte[] register, boolean resultWasMoved,
                                      int fuzzyLevel, int fuzzyLevelOffset, LinkedList<BasicBlock> path,
                                      SliceNode sliceNode) throws DetectionLogicError, SyntaxException {
    final CodeLine cl = bb.getCodeLines().get(index);
    final Instruction i = cl.getInstruction();

    // Verify that the codeline instruction is indeed an INVOKE
    if (!(i.getType() == InstructionType.INVOKE || i.getType() == InstructionType.INVOKE_STATIC)) {
      throw new DetectionLogicError("handleInvokeForward: Wrong instruction, need INVOKE, but got: " + cl);
    }

    // Check if the invoked method is available within the application scope
    boolean isMethodKnown = true;
    Method invokedMethod = null;
    byte[][] cmp2 = i.getCalledClassAndMethodWithParameter();
    String cmp2Class = new String(cmp2[0]);
    String cmp2Method = new String(cmp2[1]);
    try {
      invokedMethod = app.getMethodByClassAndName(cmp2Class, cmp2Method, cmp2[2], cmp2[3]);
    } catch (ClassOrMethodNotFoundException e) {
      LOGGER.debug("handleInvokeForward: Unable to forwardTrack into method. {}", e.getMessage());
      isMethodKnown = false;
    }

    // Get the position of the tracked register within the INVOKE statement
    int trackPos = 0;
    for (; trackPos < i.getInvolvedRegisters().size(); trackPos++) {
      if (Arrays.equals(register, i.getInvolvedRegisters().get(trackPos)))
        break;
    }

    // Whitelist
    boolean isMethodWhiteListed = false;
    if (!isMethodKnown) {
      if (cmp2Class.equals("java/lang/System") && cmp2Method.equals("arraycopy") &&
          Arrays.equals(cmp2[2], "Ljava/lang/Object;ILjava/lang/Object;II".getBytes()) && Arrays.equals(cmp2[3], "V".getBytes())) {
        if (trackPos == 0) { // src
          LOGGER.debug("handleInvokeForward: Found System->arraycopy(...). Continuing with dest register {}",
              new String(i.getInvolvedRegisters().get(2)));
          TodoList.RegisterSearch rs1 = new TodoList.RegisterSearch(i.getInvolvedRegisters().get(2), bb, index, fuzzyLevel,
              fuzzyLevelOffset, new LinkedList<>(path), sliceNode, register);
          todoList.addRegisterToTrack(rs1);
        }
        isMethodWhiteListed = true;
      }
    }

    if (isMethodKnown && !invokedMethod.isNative()) {
      // Find the code line which is first using the parameter
      TodoList.RegisterSearch rs1 = new TodoList.RegisterSearch(("p" + trackPos).getBytes(), invokedMethod.getFirstBasicBlock(), -1, fuzzyLevel,
          fuzzyLevelOffset, new LinkedList<>(path), sliceNode, register);
      todoList.addRegisterToTrack(rs1);
    } else if (isMethodWhiteListed) {
      isMethodKnown = true;
    } else {
      /*
       * Treat the invoked method as a constant for our register as the result was moved to it.
       * However, we can not track into the method (SMALI file not available).
       */
      try {
        LOGGER.debug("handleInvokeForward: Adding constant for cl = {}", cl);
        Constant c;
        if (isMethodKnown && invokedMethod.isNative())
          c = new Constant(cl, fuzzyLevel, path, searchId, Constant.ConstantType.NATIVE_METHOD);
        else
          c = new Constant(cl, fuzzyLevel, path, searchId);

        currentSliceTree.addConstant(c, bb, sliceNode, register);
        criterion.addFoundConstant(searchId, c);
      } catch (SyntaxException e) {
        LOGGER.error("handleInvokeForward: Could not add found method to found constants", e);
        criterion.logException(e);
      }
    }

    return isMethodKnown;
  }

  public List<CodeLine> findInvokes(byte[][] cmp) throws DetectionLogicError {
    List<TodoList.RegisterSearch> invokes = findObjectInvokes(cmp);

    List<CodeLine> codeLines = new ArrayList<>(invokes.size());
    for (TodoList.RegisterSearch rs : invokes) {
      codeLines.add(rs.getBB().getCodeLines().get(rs.getIndex()+1));
    }

    return codeLines;
  }

  private List<TodoList.RegisterSearch> findObjectInvokes(byte[][] cmp) throws DetectionLogicError {
    List<TodoList.RegisterSearch> rsList = new ArrayList<>();

    for (SmaliClass smaliClass : app.getAllSmaliClasses()) {
      for (Method m : smaliClass.getMethods()) {
        //LOGGER.debug("Looking in method: " + rawFile.getName() + "." + m.getName() + "()");
        for (BasicBlock bb : m.getBasicBlocks()) {
          for (CodeLine cl : bb.getCodeLines()) {
            Instruction i = cl.getInstruction();

            // Search for the actual invoke instruction
            if (i.getType() == InstructionType.INVOKE || i.getType() == InstructionType.INVOKE_STATIC) {
              if ( (Arrays.equals(cmp[0], WILDCARD) || Arrays.equals(i.getCalledClassAndMethodWithParameter()[0], cmp[0]))
                  && Arrays.equals(i.getCalledClassAndMethodWithParameter()[1], cmp[1]) ) {
                // Found a method with correct invoke
                // invoke-direct {v0}, Landroid/content/IntentFilter;-><init>()V
                LOGGER.debug("Method {}->{} invokes {}->{}({}) on line {}",
                    smaliClass.getFullClassName(true), m.getName(), new String(cmp[0]), new String(cmp[1]),
                    new String(i.getCalledClassAndMethodWithParameter()[2]), cl.getLineNr());

                List<byte[]> regs = i.getInvolvedRegisters();
                if (!regs.isEmpty()) {
                  byte[] register = regs.get(0);
                  int index = bb.getCodeLines().indexOf(cl);
                  TodoList.RegisterSearch rs = new TodoList.RegisterSearch(register, bb, index-1, 0, 0,
                      new LinkedList<BasicBlock>(), null, null);
                  rsList.add(rs);
                }
              }
              // else: Invoke did not match.
            }
          }
        }
      }
    }

    return rsList;
  }

  private LinkedList<TodoList.RegisterSearch> findConstantId(String constantId) {
    LinkedList<TodoList.RegisterSearch> rsList = new LinkedList<>();

    for (SmaliClass smaliClass : app.getAllSmaliClasses()) {
      for (Method m : smaliClass.getMethods()) {
        //LOGGER.debug("Looking in method: " + rawFile.getName() + "." + m.getName() + "()");
        for (BasicBlock bb : m.getBasicBlocks()) {
          for (CodeLine cl : bb.getCodeLines()) {
            Instruction i = cl.getInstruction();

            // Search for the actual constant assignment
            if (i.getType() == InstructionType.CONST) {
              LinkedList<byte[]> splittedCl = Instruction.split(cl.getLine());
              byte[] constRegister = splittedCl.get(1);
              byte[] constValue = splittedCl.getLast();

              if (Arrays.equals(constValue, constantId.getBytes())) {
                LOGGER.debug("Method {}->{} contains {} in register {} on line {}", smaliClass.getFullClassName(true),
                    m.getName(), new String(constValue), new String(constRegister), cl.getLineNr());

                int index = bb.getCodeLines().indexOf(cl);
                TodoList.RegisterSearch rs1 = new TodoList.RegisterSearch(constRegister, bb, index, 0, 0,
                    new LinkedList<BasicBlock>(), null, constRegister);
                rsList.add(rs1);
              } // else: constant did not match
            }
          }
        }
      }
    }

    return rsList;
  }

  private Map<CodeLine, byte[][]> findFieldId(String constantId) {
    Map<CodeLine, byte[][]> fieldMap = new HashMap<>();

    for (SmaliClass smaliClass : app.getAllSmaliClasses()) {
      List<Field> fields = smaliClass.getAllFields();
      for (Field field : fields) {
        byte[] cl = field.getCodeLine().getLine();

        int equalSignIndex = Bytes.indexOf(cl, (byte) '=');
        if (equalSignIndex > 0) {
          String fieldValue = new String(ByteUtils.subbytes(cl, equalSignIndex + 2));
          if (fieldValue.equals(constantId)) {
            LOGGER.debug("findFieldId: {} with field value {}", field.getFieldName(), fieldValue);
            byte[][] cf = new byte[2][];
            cf[0] = smaliClass.getFullClassName(false).getBytes();
            cf[1] = field.getFieldName().getBytes();
            fieldMap.put(field.getCodeLine(), cf);
          }
        }
      }
    }

    return fieldMap;
  }
}
