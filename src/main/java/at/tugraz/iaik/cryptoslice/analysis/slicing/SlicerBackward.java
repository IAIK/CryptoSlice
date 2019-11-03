package at.tugraz.iaik.cryptoslice.analysis.slicing;

import at.tugraz.iaik.cryptoslice.application.*;
import at.tugraz.iaik.cryptoslice.application.instructions.Constant;
import at.tugraz.iaik.cryptoslice.application.instructions.Instruction;
import at.tugraz.iaik.cryptoslice.application.instructions.InstructionType;
import at.tugraz.iaik.cryptoslice.application.methods.BasicBlock;
import at.tugraz.iaik.cryptoslice.application.methods.Method;
import at.tugraz.iaik.cryptoslice.utils.ByteUtils;
import at.tugraz.iaik.cryptoslice.utils.FileList;

import java.io.File;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;

public class SlicerBackward extends Slicer {
  public SlicerBackward(Application app, List<CodeLine> searchIds) {
    super(app, searchIds);
  }

  /**
   * Search the application code for a calls/invokes to a given class and method and
   * determine all constants which can be assigned to a given parameter.
   *
   * Errors which occur during the search will be logged but will not abort
   * all sub-searches, only the currently failing one!
   *
   * This method will build the def-use chains (slices).
   *
   * WARNING: This method is not threadsafe!
   *
   * @param criterion the request to search for, results will be added to this request
   * @throws at.tugraz.iaik.cryptoslice.application.DetectionLogicError if the register index is not appropriate or if
   * the search does not seem to terminate.
   */
  @Override
  public void startSearch(SlicingCriterion criterion) throws DetectionLogicError {
    this.criterion = criterion;

    SlicingPatternBT patternBT = (SlicingPatternBT) criterion.getPattern();
    int regToTrack = patternBT.getParameterOfInterest();
    this.cmp = patternBT.getCmp();

    if (regToTrack < 0 || regToTrack > 65535)
      throw new DetectionLogicError("Register index must not be negative or too big!");

		/*
		 * Get a list of all invokes and start a search for each one. Each search gets a unique searchId which is assigned to all
		 * constants which are found for the corresponding register/invoke. Each with a new empty path list
		 */
    List<TodoList.RegisterSearch> rsList = new ArrayList<>();

    // Only search for invokes if no return value should be tracked
    if (patternBT.getTrackReturnValue() == null) {
      if (patternBT.getCodeLine() != null) {
        rsList = findInvokeInCodeLine(patternBT.getCodeLine(), cmp, regToTrack, 0, new LinkedList<BasicBlock>(), null, null);
      } else {
        rsList = findInvokes(cmp, patternBT.getClassAndMethod(), regToTrack, 0, new LinkedList<BasicBlock>(), null, null);
      }
      LOGGER.debug("Found {} INVOKES for {}.{}, parameterOfInterest={}", rsList.size(), new String(cmp[0]), new String(cmp[1]), regToTrack);
    }

    for (TodoList.RegisterSearch rs : rsList) {
      currentSliceTree = new SliceTree();
      todoList = new TodoList(this);
      todoList.addRegisterToTrack(rs);

      /*
       * Set up searchid. Each Codeline where a search begins gets the same id.
       * This is useful to match Constants which are found for the same
       * invocation but for different arguments.
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

    // Alternative to searching method invocations -> Track return values
    if (patternBT.getTrackReturnValue() != null) {
      // Consider * or "null" in the parameter list cmp[0] - class name as wildcard -> null
      if (Arrays.equals(this.cmp[0], WILDCARD) || Arrays.equals(this.cmp[0], "null".getBytes()))
        this.cmp[0] = null;

      byte[][] cmp2 = { cmp[0], cmp[1], cmp[2], patternBT.getTrackReturnValue().getBytes() };

      // Limit tracking to either one specific class or search for all classes containing method cmp2[1]
      List<Method> methodsWithReturnValue = new ArrayList<>();
      if (this.cmp[0] != null) {
        try {
          Method method = app.getMethodByClassAndName(new String(cmp2[0]), new String(cmp2[1]), cmp2[2], cmp2[3]);
          methodsWithReturnValue.add(method);
        } catch (ClassOrMethodNotFoundException e) {
          LOGGER.debug("Lost Track: {}", e.getMessage());
          return;
        }
      } else {
        String methodParametersStr = (cmp2[2] != null) ? new String(cmp2[2]) : "";

        for (SmaliClass sc : app.getAllSmaliClasses()) {
          Method method = sc.getMethodByName(new String(cmp2[1]));

          if (method != null && method.getParameterString().equals(methodParametersStr) &&
              new String(method.getReturnValue()).equals(new String(cmp2[3]))) {
            methodsWithReturnValue.add(method);
          }
        }
      }

      for (Method m : methodsWithReturnValue) {
        cmp2[0] = m.getSmaliClass().getFullClassName(false).getBytes(); // set current class

        LOGGER.debug("Will backtrack RETURN values from {}.{}", new String(cmp2[0]), new String(cmp2[1]));

        currentSliceTree = new SliceTree();
        todoList = new TodoList(this);
        todoList.addReturnValuesFromMethod(cmp2, 0, 0, new LinkedList<BasicBlock>(), null, null);

        CodeLine cl = m.getCodeLines().get(0);
        searchId = searchIds.indexOf(cl);
        if (searchId == -1) {
          searchIds.add(cl);
          searchId = searchIds.size() - 1;
        }

        startTracking();

        if (!currentSliceTree.getSliceNodes().isEmpty())
          this.criterion.addToSliceTress(searchId, currentSliceTree);
      }
    }
  }

  /**
   * Start the search. Search until the TodoList is empty. It may be "refilled" during each run.
   *
   * @throws DetectionLogicError
   */
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
          backtrackRegister(rs);
        } else if (todoList.hasRemainingReturnValuesFromMethods()) {
          TodoList.ClassContentTracker ctt =  todoList.getNextReturnValuesFromMethod();

          try {
            Method m = app.getMethodByClassAndName(new String(ctt.getCi()[0]), new String(ctt.getCi()[1]), ctt.getCi()[2], ctt.getCi()[3]);
            addAllReturnedRegistersFromMethod(m, ctt); // parse all return values
          } catch (ClassOrMethodNotFoundException e) {
            LOGGER.debug("Lost Track: {}", e.getMessage());
          }

        } else if (todoList.hasRemainingFieldsToTrack()) {
          TodoList.ClassContentTracker ctt = todoList.getNextField();
          backTrackField(ctt);
        } else if (todoList.hasRemainingArraysToTrack()) {
          TodoList.ClassContentTracker ctt = todoList.getNextCaToTrack(); // ctt contains classname, arrayname etc
          findArrayGets(ctt); // find all codelines where an array is accessed after it was loaded
          findArrayPuts(ctt); // find all codelines where an array is created and accessed and later stored
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

  /**
   * This method does the normal backtracking of a register in a BasicBlock. It will search through the
   * BasicBlock and track access to the given register. It will act appropriate to the found opcodes.
   *
   * @throws SyntaxException
   * @throws DetectionLogicError
   */
  private void backtrackRegister(final TodoList.RegisterSearch rs) throws SyntaxException, DetectionLogicError {
    byte[] register = rs.getRegister();
    BasicBlock bb = rs.getBB();
    int actualLine = rs.getIndex();

    LOGGER.debug("backtrackRegister: reg={}, actualLine={}", new String(register),
        rs.getBB().getCodeLines().get(rs.getIndexAbsolute()).getLineNr());

    /*
		 * Safeguards:
		 * - In TodoList: If the fuzzy level is too high, skip the request as the results would get too bloated.
		 * - Here: If the method is not static and p0 is tracked, abort tracking. p0 is the this-reference and
		 * this will most likely mess things up, as every called method on the corresponding class etc would be tracked.
		 */
    if (!bb.getMethod().isStatic() && Arrays.equals(P0_THIS, register)) {
      LOGGER.debug("backtrackRegister: Will not track p0 in non-static method ({})", bb.getMethod().getName());
      return;
    }

    final LinkedList<BasicBlock> path = rs.getPath();
    if (path.isEmpty() || !(path.getLast() == bb)) {
      // add the current BB to the path but no duplicates (at the end)
      path.addLast(bb);
    }

    // Add the currently tracked register to the SliceTree
    SliceNode sliceNode = currentSliceTree.addNode(rs);

		/*
		 * Check all opcodes in the BB.
		 * actualLine points to the CodeLine which was found in the previous search.
		 * The next opcode of interest is any previous opcode which relates to the tracked register.
		 * A procedure after this while loop handles the case when the beginning of a BB is reached.
		 */
    while (actualLine > 0) { // look at all code lines in this BB
      CodeLine cl = bb.getCodeLines().get(--actualLine); // look at the previous instruction

      // skip all non-code lines
      if (!cl.isCode()) continue;

      Instruction i = cl.getInstruction(); // get the instruction and work with it
      LOGGER.trace("backtrackRegister: Checking codeline {}", cl);

      switch (i.getType()) {
        case AGET:
          if (Arrays.equals(i.getResultRegister(), register)) {
            // entering arraymode
            byte[] arrayReg = i.getInvolvedRegisters().get(0);
            LOGGER.debug("AGET case, entering ARRAY mode, arrayReg={}", new String(arrayReg));
            arrayMode(arrayReg, actualLine, rs.getFuzzyLevel(), rs.getFuzzyOffset(), new LinkedList<BasicBlock>(path), sliceNode, rs.getRegister());
            LOGGER.debug("Finished ARRAY mode");
            return; // abort here, backtracking array accesses etc which were not found in arrayMode-method the will be done later on
          }
          break;

        case APUT:
          if (Arrays.equals(i.getResultRegister(), register)) {
            /*
					   * We are backtracking an array object and something is written to this array. We therefore also backtrack
					   * the register which is APUTted into our array and continue our search. The current search will likely end
					   * when a new-array instruction is found with our register being the new array register.
					   */
            LOGGER.debug("Found an APUT. Seems we are backtracking an array, so we will also backtrack the putted register!");
            TodoList.RegisterSearch rs2 = new TodoList.RegisterSearch(i.getInvolvedRegisters().get(0), bb, actualLine,
                rs.getFuzzyLevel(), rs.getFuzzyOffset(), new LinkedList<BasicBlock>(path), sliceNode, rs.getRegister());
            todoList.addRegisterToTrack(rs2);
          }
          continue;

        case CONST:
          if (Arrays.equals(i.getResultRegister(), register)) {
            Constant c = new Constant(cl, rs.getFuzzyLevel(), new LinkedList<BasicBlock>(path), searchId);
            criterion.addFoundConstant(searchId, c);
            currentSliceTree.addConstant(c, bb, sliceNode, register);
            LOGGER.debug("backtrackRegister: Found const! cl={}", cl);
            return;
          }
          break;

        case FILL_ARRAY_DATA:
          if (Arrays.equals(register, i.getResultRegister())) {
            Constant c = new Constant(cl, rs.getFuzzyLevel(), new LinkedList<BasicBlock>(path), searchId);
            criterion.addFoundConstant(searchId, c);
            currentSliceTree.addConstant(c, bb, sliceNode, register);
            LOGGER.debug("backtrackRegister: Found a FILL_ARRAY_DATA constant! {}", cl);
            return;
          }
          break;

        case GET: // Some field is loaded into our register
          if (Arrays.equals(i.getResultRegister(), register)) {
            // Parse the fieldname+class
            byte[][] cf = Instruction.parseClassAndField(i.getInvolvedFields().get(0));
            todoList.addField(cf, rs.getFuzzyLevel(), rs.getFuzzyOffset(), new LinkedList<BasicBlock>(path), sliceNode, rs.getRegister());
            LOGGER.debug("backtrackRegister: GET case, will later backtrack cf={}.{}", new String(cf[0]), new String(cf[1]));
            return;
          }
          continue;

        case GOTO:
        case IGNORE:
        case NOP:
          continue;

        case INTERNAL_SMALI_OPCODE:
          /*
           * This could be a valid operation if, eg. array-length is used in a weird way or if an Exception is used in
           * some tracked method etc. If the register matches, we stop here.
           * Adding a constant does not make sense because this opcode serves no valuable statement.
           */
          if (Arrays.equals(i.getResultRegister(), register)) {
            LOGGER.debug("backtrackRegister: Lost track (INTERNAL_SMALI_OPCODE). The register is overwritten.");
            /*LOGGER.info("backtrackRegister: Found an internal method which overwrote our register "
                + new String(register) + ". Adding as constant! cl=" + cl);
            Constant c = new Constant(cl, rs.getFuzzyLevel(), new LinkedList<BasicBlock>(path), searchId);
            criterion.addFoundConstant(c);
            currentSliceTree.addConstant(c, bb, sliceNode, rs.getPreviousRegister());*/
            return;
          }
          continue;

        case INVOKE_STATIC:
        case INVOKE:
          // Check if this invoke involves our currently searched method, if so, we do not need to investigate anything else
          if (Arrays.equals(i.getCalledClassAndMethodWithParameter()[0], cmp[0])
              && Arrays.equals(i.getCalledClassAndMethodWithParameter()[1], cmp[1])
              && (cmp[2] == null || Arrays.equals(i.getCalledClassAndMethodWithParameter()[2], cmp[2])
          )) {
            continue;
          }

          // Check if our register is involved in this invoke opcode.
          // A method can also be invoked on an object, eg. StringBuilder.append, therefore start with the first one.
          boolean found = false;
          for (byte[] involvedReg : i.getInvolvedRegisters()) {
            if (Arrays.equals(register, involvedReg)) {
              found = true;
              break;
            }
          }

          if (found) {
            /*
					   * We now track all return values from this method. In order to not track too many constants
             * which might be unrelated, we set a large offset to the fuzzy value. This way, the fuzzy
             * value in the results will be "normal", but if the fuzzyValue+offset gets too large, further
             * searches will be cancelled. Since we do not know what happens in the methods, we do not
             * want to track into methods which call the found found method and so on. We therefore set
             * the offset to the maximum-3.
             */
            int fuzzyLevelOffset = rs.getFuzzyLevel();
            if (fuzzyLevelOffset < TodoList.MAX_FUZZY_LEVEL-3)
              fuzzyLevelOffset = TodoList.MAX_FUZZY_LEVEL-3;

            handleInvoke(bb, actualLine, register, false, rs.getFuzzyLevel(),
                fuzzyLevelOffset, new LinkedList<BasicBlock>(path), sliceNode);
          }
          continue;

        case JMP: // Ignored because JMPs just start/end BasicBlocks
          continue;

        case MATH_1: // Unary operations with only 1 target and 1 source reg
          if (Arrays.equals(i.getResultRegister(), register)) {
            byte[] involvedReg  = i.getInvolvedRegisters().get(0); // track the register which got applied to our old register
            if (!Arrays.equals(register, involvedReg)) {
              LOGGER.debug("backtrackRegister: 2nd register is different from target, now tracking: {}", new String(involvedReg));
              register = involvedReg;
            } else {
              LOGGER.debug("backtrackRegister: 2nd register is the same as the tracked one, keep on tracking {}", new String(register));
            }
          }
          continue;

        case MATH_2: // Binary operations with 1 target and 2 sources
          if (Arrays.equals(i.getResultRegister(), register)) {
            byte[] involvedReg1 = i.getInvolvedRegisters().get(0);
            byte[] involvedReg2 = i.getInvolvedRegisters().get(1);

            // Check if only one or both register are different
            if (Arrays.equals(register, involvedReg1))
              involvedReg1 = null;
            if (Arrays.equals(register, involvedReg2))
              involvedReg2 = null;

            // Track one register directly and add the second one as a new RS.
            TodoList.RegisterSearch rs2;
            if (involvedReg1 != null && involvedReg2 != null) {
              LOGGER.debug("backtrackRegister: 2nd register is different from target, now tracking: {}", new String(involvedReg1));
              register = involvedReg1;
              rs2 = new TodoList.RegisterSearch(involvedReg2, bb, actualLine, rs.getFuzzyLevel(),
                  rs.getFuzzyOffset(), new LinkedList<BasicBlock>(path), sliceNode, rs.getRegister()); // first and only operand register
              todoList.addRegisterToTrack(rs2); // Keep on track with this register
              LOGGER.debug("backtrackRegister: Adding RS for 3rd register: " + new String(involvedReg2));
            }
            else if (involvedReg1 != null) {
              LOGGER.debug("backtrackRegister: Only 2nd register is different from tracked one, keep on tracking {}", new String(involvedReg1));
              rs2 = new TodoList.RegisterSearch(involvedReg1, bb, actualLine, rs.getFuzzyLevel(),
                  rs.getFuzzyOffset(), new LinkedList<BasicBlock>(path), sliceNode, rs.getRegister()); // first and only operand register
              todoList.addRegisterToTrack(rs2); // Keep on track with this register
            }
            else if (involvedReg2 != null) {
              LOGGER.debug("backtrackRegister: Only 3rd register is different from tracked one, keep on tracking {}", new String(involvedReg2));
              rs2 = new TodoList.RegisterSearch(involvedReg2, bb, actualLine, rs.getFuzzyLevel(),
                  rs.getFuzzyOffset(), new LinkedList<BasicBlock>(path), sliceNode, rs.getRegister()); // first and only operand register
              todoList.addRegisterToTrack(rs2); // Keep on track with this register
            }
          }
          continue;

        case MATH_2C: // Binary operations with 1 target, 1 source and 1 constant instead of register
          if (Arrays.equals(i.getResultRegister(), register)) {
            /*Constant c = new Constant(cl, rs.getFuzzyLevel(), new LinkedList<BasicBlock>(path), searchId);
            criterion.addFoundConstant(searchId, c);
            currentSliceTree.addConstant(c, bb, sliceNode, rs.getPreviousRegister());
            LOGGER.debug("backtrackRegister: Found MATH const! cl=" + cl);*/

            byte[] involvedReg = i.getInvolvedRegisters().get(0);
            if (!Arrays.equals(register, involvedReg)) {
              LOGGER.debug("backtrackRegister: 2nd register is different from target, now tracking: {}", new String(involvedReg));
              register = involvedReg;
            } else {
              LOGGER.debug("backtrackRegister: 2nd register is the same as the tracked one, keep on tracking {}", new String(register));
            }
          }
          continue;

        case MOVE:
          if (Arrays.equals(i.getResultRegister(), register)) {
            register = i.getInvolvedRegisters().get(0); // track the register which got moved to our old register
            LOGGER.debug("backtrackRegister: MOVE - now tracking {}", new String(register));
          }
          continue;

        case MOVE_RESULT:
          /*
           * MOVE_RESULT opcodes are moving results from INVOKES or FILLED_NEW_ARRAY opcodes into a register.
           * If we have a MOVE_RESULT opcode, we need to find the previous opcode and handle it appropriately.
           */
          if (Arrays.equals(i.getResultRegister(), register)) {
            LOGGER.debug("MOVE_RESULT case");
            BasicBlock.FoundCodeLine fcl = BasicBlock.getPreviousOpcode(bb, cl);

            // We have to fix the path if we found it in another BB
            LinkedList<BasicBlock> fixedPath = new LinkedList<BasicBlock>(path);
            if (fixedPath.getLast() != fcl.getBasicBlock()) {
              fixedPath.addLast(fcl.getBasicBlock());
            }

            Instruction ii = fcl.getCodeLine().getInstruction();
            if (ii.getType() == InstructionType.INVOKE || ii.getType() == InstructionType.INVOKE_STATIC) {
              LOGGER.debug("  Found INVOKE");
              handleInvoke(fcl.getBasicBlock(), fcl.getIndex(), register, true, rs.getFuzzyLevel(), rs.getFuzzyOffset(), fixedPath, sliceNode);
              return;
            } else if (ii.getType() == InstructionType.FILLED_NEW_ARRAY) {
              LOGGER.debug("  Found FILLED_NEW_ARRAY");
              handleFilledNewArray(fcl.getBasicBlock(), fcl.getCodeLine(), fcl.getIndex(), rs.getFuzzyLevel(), rs.getFuzzyOffset(), fixedPath, sliceNode, register);
              return;
            } else {
              throw new DetectionLogicError("MOVE_RESULT: The previous opcode was not invoke-x nor filled-new-array! cl=" + fcl.getCodeLine());
            }
          }
          continue;

        case NEW_ARRAY:
        case NEW_INSTANCE:
          if (Arrays.equals(i.getResultRegister(), register)) {
            LOGGER.debug("backtrackRegister: Lost track (new-instance/array). The register is overwritten.");
            return;
          }
          continue;

        case PUT:
          /*
           * We can ignore PUTs as our tracked register is only copied to a field. If this field matters,
           * it will get tracked later on (or was already) if this field shows up somewhere else where
           * it is loaded (GET).
           */
          continue;

        case RETURN:
          /*
           * If we find a return in the middle of the BB the following might have happened:
           *
           * 1) Someone patched the code and premature returns something. This if fine
           * and the dex parser/optimizer will not complain about this. But this
           * yields to dead code in at least the patched BB.
           *
           * 2) We find a return as the last statement in a block (no dead code) and the
           * current BB is a try block and the last BB where we are coming from is a
           * catch block, this is also fine. Although the return will not throw any
           * exception, the code is fine. Normally the BB would reside in another BB
           * with appropriate goto statements and labels.
           *
           * 3) A return normally ends the BB and no outgoing edge should be there such
           * that we cannot find this BB by a backwards search. This is the normal case.
           */
          if (!bb.hasDeadCode()) {
            boolean error = true;
            if (path.size() > 1) {
              int index = path.size()-2;
              BasicBlock lastBB = path.get(index);
              if (lastBB.isCatchBlock() && bb.isTryBlock()) {
                /*
                 * We are in a try block, the last one is a catch block and the return is the last opcode.
                 * The search continues here.
                 */
                error = false;
                LOGGER.debug("Ignoring RETURN, try/catch and no dead code.");
                //throw new DetectionLogicError("Ignoring RETURN, try/catch and no dead code.");
              }
            }
            if (error) {
              // this should not happen
              throw new DetectionLogicError("Found unexpected RETURN opcode! cl=" + cl/* + "in file:" + cl.getSmaliClass().getFile().getAbsolutePath() + " in method:" + cl.getMethod()*/);
            }
          } else {
            // Some patched a return?
            LOGGER.info("Found a RETURN opcode and dead code. Method patched/cracked?! Aborting this search.");
            return;
          }
          // fall through
        default:
          LOGGER.debug("Did not handle opcode " + i.getType() + "/" + new String(i.getOpCode()) + " (default)");
      }
    } // while end

    /*
     * We reached the beginning of the BB, now check if we also reached the beginning of the method.
     * If so and if we are tracking a pX register, we will backtrack access to this
     * (the current) method with the corresponding parameter index.
     */
    LinkedList<BasicBlock> previousBBs = bb.getPreviousBB();
    if (previousBBs == null || previousBBs.isEmpty()) { // We reached the beginning of a method
      LOGGER.debug("Reached end of BB and are in the first BB of the method.");

      if (ByteUtils.startsWith(register, new byte[]{'p'})) {
        // We have a parameter index, pX. We now need to look at calls for this method with the corresponding parameter.
        int parameterIndex = Integer.parseInt(new String(register).substring(1)); // cut the 'p'

        if (!bb.getMethod().isStatic()) {
          /*
           * p0 is the class instance if the method is not static, otherwise
           * it is the first parameter. Method parameters start at 0, so we have to
           * subtract 1 if we are not in a static method, because of p0 and therefore p1
           * being the first parameter.
           */
          parameterIndex--;
          LOGGER.debug("We're NOT inside a STATIC method and are searching {}: decreasing parameter index to {}",
              new String(register), parameterIndex);
        }

        byte[][] method = bb.getMethod().getCmp();
        LOGGER.debug("Searching for INVOKES to method {}.{}, parameterIndex={}", new String(method[0]),
            new String(method[1]), parameterIndex);

        // Search invocations of the current class in method[0]
        List<TodoList.RegisterSearch> foundInvokes = findInvokes(method, null, parameterIndex, rs.getFuzzyLevel(),
            new LinkedList<BasicBlock>(path), sliceNode, register);

        // Search invocations in subclasses if the class is abstract
        if (bb.getMethod().getSmaliClass().isAbstract() && !bb.getMethod().isPrivate()) {
          for (SmaliClass smaliClass : app.getAllSmaliClasses()) {
            if (smaliClass.extendsClass(bb.getMethod().getSmaliClass().getFullClassName(false))) {
              boolean methodIsOverwritten = false;
              for (Method smaliMethod : smaliClass.getMethods()) {
                // Ensure the subclass does not redefine the method
                if (smaliMethod.getName().equals(bb.getMethod().getName()) &&
                    smaliMethod.getParameterString().equals(bb.getMethod().getParameterString()) &&
                    smaliMethod.getReturnValueString().equals(bb.getMethod().getReturnValueString())) {
                  LOGGER.debug("Subclass " + smaliClass.getFullClassName(false) + " overwrites the method declaration of the superclass");
                  methodIsOverwritten = true;
                  break;
                }
              }

              if (!methodIsOverwritten) {
                byte[][] subClassedMethod = bb.getMethod().getCmp();
                subClassedMethod[0] = smaliClass.getFullClassName(false).getBytes();
                foundInvokes.addAll(findInvokes(subClassedMethod, null, parameterIndex, rs.getFuzzyLevel(),
                    new LinkedList<BasicBlock>(path), sliceNode, register));
              }
            }
          }
        }

        for (TodoList.RegisterSearch rsInv : foundInvokes) {
          rsInv.setFuzzyOffset(rs.getFuzzyOffset());
          todoList.addRegisterToTrack(rsInv);
        }

        LOGGER.debug(" Found {} INVOKES for our method {}.{}, parameterIndex={}", foundInvokes.size(),
            new String(method[0]), new String(method[1]), parameterIndex);

        /*
         * If the method is never invoked, it is likely called over java.lang.reflect or is some entry point from, eg, the Android
         * framework as android.content.BroadcastReceiver.onReceive(..) would be. We store this info and treat it as a constant.
         */
        if (foundInvokes.isEmpty()) {
          LOGGER.debug("   Saving this method as a CONSTANT because no invokes were found.");
          // store the class and the method with the signature etc as the value, also save the register, eg, p1
          String value = bb.getMethod().getReadableJavaName() + ", parameterIndex=" + parameterIndex;
          Constant c = new Constant(bb.getMethod().getCodeLines().getFirst(), rs.getFuzzyLevel(), path, searchId, Constant.ConstantType.UNCALLED_METHOD, value);
          criterion.addFoundConstant(searchId, c);
          currentSliceTree.addConstant(c, bb, sliceNode, rs.getPreviousRegister());
        }
      } else {
        LOGGER.debug(" Lost track of reg {}, no more BBs available (reached method beginning?)", new String(register));
      }
    } else {
      /*
       * Search for the register in all BBs "above" this one because we reached the beginning of the actual BB.
       * Do this with a new RS object because that way we do not look into a BB more than once for the same register.
       */
      LOGGER.debug("Reached end of BB, adding RS for all previous blocks.");

      for (BasicBlock bbb : previousBBs) {
        // bbb.getCodeLines().size() is an invalid index, but it will be decremented in the main loop before anything happens
        TodoList.RegisterSearch rs2 = new TodoList.RegisterSearch(register, bbb, bbb.getCodeLines().size(),
            rs.getFuzzyLevel(), rs.getFuzzyOffset(), new LinkedList<BasicBlock>(path), sliceNode, rs.getRegister());
        todoList.addRegisterToTrack(rs2); // search in this BB (add to to-do list)
      }
    }
  }

  /**
   * Find all PUTs to a given field from a given class. All PUTs are added to the TodoList as a RegisterSearch object.
   * This way, all values are found which are written to a given field.
   *
   * @param ctt the class content tracker
   * @throws SyntaxException if a Constant could not be created for a Field
   */
  private void backTrackField(TodoList.ClassContentTracker ctt) throws SyntaxException {
    byte[][] cf = ctt.getCi();
    LOGGER.debug("Backtracking field {}.{}", new String(cf[0]), new String(cf[1]));

    SmaliClass sf = app.getSmaliClassByClassName(new String(cf[0]));
    if (sf == null) {
      LOGGER.debug("backTrackField: Lost track, FIELD (or class) not available, class={}", new String(cf[0]));
      return;
    }

    for (Field f : sf.getAllFields()) {
      LOGGER.trace("Checking field {} in {}", f.getFieldName(), sf.getFile().getName());

      if (f.getFieldName().equals(new String(cf[1]))) {
        LOGGER.trace(" ...it matches our pattern!");

        boolean isFinalAndStatic = f.isFinal() && f.isStatic();
        if (isFinalAndStatic) {
          // we already have the constant because it is assigned in the field declaration
          Constant c = new Constant(f.getCodeLine(), ctt.getFuzzyLevel(), ctt.getPath(), searchId);
          if (c.getValue() != null) { // if null, something gets assigned in <clinit>
            criterion.addFoundConstant(searchId, c);
            currentSliceTree.addConstant(c, null, ctt.getPreviousSliceNode(), ctt.getPreviousRegister());
            LOGGER.trace(" ...added to result list because it is static and final with value! We are done.");
            return; // we are done
          }
        }

        if (f.isStatic()) {
          // the value could also have been assigned to a static field in the field declaration
          Constant c = new Constant(f.getCodeLine(), ctt.getFuzzyLevel(), ctt.getPath(), searchId);
          if (c.getValue() != null) { // if null, something gets assigned in <clinit>
            criterion.addFoundConstant(searchId, c);
            currentSliceTree.addConstant(c, null, ctt.getPreviousSliceNode(), ctt.getPreviousRegister());
            LOGGER.trace(" ...added to result list because it is static with value!");
            // no return here because there could be other assignments via XPUT
          }
        }

        if (isFinalAndStatic)
          LOGGER.trace(" ..found a static and final constant without any assigned value, need to parse <clinit>!");
        else
          LOGGER.trace(" ...not constant and static, checking field access!");

				/*
				 * If the field is final, it will get its value assigned in the constructor (<init>).
				 * We could be ssmart and parse only the constructor, but we are lazy and search for
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
            if (isFinalAndStatic && !Arrays.equals(Method.STATIC_CONSTRUCTOR_NAME, m.getName().getBytes()))
              continue; // we only need to look into <clinit>.

            for (BasicBlock bb : m.getBasicBlocks()) {
              for (int i = 0; i < bb.getCodeLines().size(); i++) { // look at all put opcodes in all BBs
                CodeLine cl = bb.getCodeLines().get(i);
                Instruction instr = cl.getInstruction();
                if (instr.getType() == InstructionType.PUT) {
                  // check the classname and fieldname
                  if (Arrays.equals(cf[0], instr.getResultField()[0])	&& Arrays.equals(cf[1], instr.getResultField()[1])) {
                    // we have a PUT opcode which puts into our field
                    LOGGER.debug("backTrackField:   Found a valid xPUT in {}.{}(...), adding reg {} to TodoList, cl={}",
                        sf2.getFile().getName(), m.getName(), new String(instr.getInvolvedRegisters().get(0)), cl);

                    LinkedList<BasicBlock> newPath = new LinkedList<BasicBlock>(ctt.getPath());
                    newPath.addLast(bb); // add the found BB to the path

                    TodoList.RegisterSearch rs = new TodoList.RegisterSearch(instr.getInvolvedRegisters().get(0), bb, i,
                        ctt.getFuzzyLevel(), ctt.getFuzzyOffset(), newPath, ctt.getPreviousSliceNode(), ctt.getPreviousRegister()); // there is only one register involved
                    todoList.addRegisterToTrack(rs); // add this reg to our todolist in order to continue search later on
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

  /**
   * Search for all RETURN opcodes in all BasicBlocks from a method and
   * add the returned register as a RegisterSearch to the TodoList.
   *
   * @param m the method to search through
   * @param ctt the ctt with additional information such as the fuzzy level
   * @throws DetectionLogicError if the returned register in the return-opcode cannot be parsed
   */
  private void addAllReturnedRegistersFromMethod(Method m, TodoList.ClassContentTracker ctt) throws DetectionLogicError {
    for (BasicBlock bb : m.getBasicBlocks()) {
      for (int i = 0; i < bb.getCodeLines().size(); i++) {
        CodeLine cl = bb.getCodeLines().get(i);
        Instruction ii = cl.getInstruction();

        if (ii.getType() == InstructionType.RETURN) {
					/*
					 * We found a RETURN and will track the returned register later.
					 *
					 * Some smali code uses return-void in non void method.
					 * Will this simply return null?
					 * Anyway, just stop here and handle the Nullpointer as no register is returned!
					 *
					 * Example from:
					 * Lcom/nd/net/netengine/BufferData; (md5: e3acc3a60...)
					 *
					 * # virtual methods
					 * .method public getByteBuffer()[B
					 * .locals 1
					 * .prologue
					 * return-void
					 * .end method
					 *
					 * .method public getFileName()Ljava/lang/String;
					 * .locals 1
					 * .prologue
					 * return-void
					 * .end method
					 */
          // add found BB to path
          LinkedList<BasicBlock> path = new LinkedList<>(ctt.getPath());
          path.addLast(bb);

          if (!ii.getInvolvedRegisters().isEmpty()) { // Prevent NP
            TodoList.RegisterSearch rs = new TodoList.RegisterSearch(ii.getInvolvedRegisters().get(0), bb, i,
                ctt.getFuzzyLevel(), ctt.getFuzzyOffset(), path, ctt.getPreviousSliceNode(), ctt.getPreviousRegister());
            todoList.addRegisterToTrack(rs);
          } else if (ii.getCodeLine().contains("return-void".getBytes())) {
            LOGGER.debug("addAllReturnedRegistersFromMethod: Found a non-void method returning with return-void!");
          } else {
            throw new DetectionLogicError("addAllReturnedRegistersFromMethod: Cannot parse returned register: " + cl);
          }
        }
      }
    }
  }

  /**
   * Handle an array which was found in an AGET opcode.
   *
   * This method performs a backward search:
   *
   * 1) If we find an APUT into arrayReg, backtrack the value register.
   * 2) If we find a NEW-ARRAY which puts a new array in arrayReg, stop.
   * 2a) If we find a FILLED_NEW_ARRAY which fills our arrayReg, we are done but we will backtrack the parameter registers.
   * 3) If we find a xGET-x, we will backtrack this array "at the end" (findArrayGets)
   * 4) If we find another opcode which overwrites arrayReg, we are screwed and something is wrong (or we are too stupid).
   *
   * @param arrayReg the array-register
   * @param codeLineIndex the index of the codeline in the BB
   * @param fuzzyLevel is the search fuzzy (inaccurate)
   * @param fuzzyLevelOffset the offset of the fuzzy value
   * @param path the current path
   * @throws SyntaxException
   * @throws DetectionLogicError
   */
  private void arrayMode(byte[] arrayReg, int codeLineIndex, int fuzzyLevel, int fuzzyLevelOffset,
                         LinkedList<BasicBlock> path, SliceNode sliceNode, byte[] previousRegister) throws SyntaxException, DetectionLogicError {
    LOGGER.debug("arrayMode: Entering");

    BasicBlockList bbl = new BasicBlockList(path, arrayReg); // backward search
    boolean firstRun = true;
    BasicBlock bb; // will be assigned to the last blocked added to the path because it is already added
    while ((bb = bbl.getNextBb()) != null) {
      //System.out.println(bbl);
      //System.out.println(" current bb: " + bb.getLabel());
      arrayReg = bbl.getState();

      if (!firstRun)
        codeLineIndex = bb.getCodeLines().size()-1; // go through the complete block, except the first
      else
        firstRun = false;

      boolean abort = false;
      while (!abort && codeLineIndex >= 0) { // search backwards
        CodeLine cl = bb.getCodeLines().get(codeLineIndex--);
        LOGGER.trace("arrayMode: array={}, cl={}", new String(arrayReg), cl);
        Instruction i = cl.getInstruction();

        switch (i.getType()) {
          case APUT:
            // Found APUT, check if it stores something in our array, if so, backtrack the register put into our array
            if (Arrays.equals(arrayReg, i.getResultRegister())) {
              LOGGER.debug("arrayMode: Found a valid APUT");
              // The value is stored into our array
              byte[] regPutIntoArray = i.getInvolvedRegisters().get(0);
              LinkedList<BasicBlock> p = new LinkedList<BasicBlock>(bbl.getPathForLastBB());
              TodoList.RegisterSearch rs = new TodoList.RegisterSearch(regPutIntoArray, bb, codeLineIndex, fuzzyLevel, fuzzyLevelOffset, p, sliceNode, previousRegister);
              todoList.addRegisterToTrack(rs);
            }
            break;

          case NEW_ARRAY:
            // This check can be fooled by smalicode which somehow reuses used arrays and move them to temporary arrays and so on...
            if (Arrays.equals(i.getResultRegister(), arrayReg)) {
              LOGGER.debug("arrayMode: Found a valid NEW_ARRAY, stop.");
              // We found the creation of the array and can therefore end our search
              bbl.removeLastBBFromList();
              abort = true;
            }
            break;

          case FILL_ARRAY_DATA:
            if (Arrays.equals(i.getResultRegister(), arrayReg)) {
              Constant c = new Constant(cl, fuzzyLevel, path, searchId);
              criterion.addFoundConstant(searchId, c);
              currentSliceTree.addConstant(c, bb, sliceNode, previousRegister);

              // We found the initialization of the array and can therefore end our search
              bbl.removeLastBBFromList();
              abort = true;
              LOGGER.debug("arrayMode: Found fill-array-data instruction, will store as constant and stop search in current BB.");
            }
            break;

          case GET:
            // check if something is copied into our array register
            if (Arrays.equals(i.getResultRegister(), arrayReg)) { // it is
              LOGGER.debug("arrayMode: Found a valid xGET-x, adding to later search. cl={}", cl);
              byte[][] ca = Instruction.parseClassAndField(i.getInvolvedFields().get(0));
              LinkedList<BasicBlock> p = new LinkedList<BasicBlock>(bbl.getPathForLastBB());
              todoList.addArrayFieldToTrack(ca, fuzzyLevel, fuzzyLevelOffset, p, sliceNode, previousRegister);
              bbl.removeLastBBFromList(); // we're done for this path
              abort = true;
            }
            break;

          case MOVE_RESULT:
            if (Arrays.equals(i.getResultRegister(), arrayReg)) {
              if (cl.getInstruction().getType() == InstructionType.MOVE_RESULT) {
                // Now check if the previous is either a FILLED_NEW_ARRAY or an INVOKE
                BasicBlock.FoundCodeLine fcl = BasicBlock.getPreviousOpcode(bb, cl);
                // We have to fix the path if we found it in another BB
                LinkedList<BasicBlock> fixedPath = bbl.getPathForLastBB();

                if (fixedPath.getLast() != fcl.getBasicBlock()) {
                  fixedPath.addLast(fcl.getBasicBlock());
                }

                if (fcl.getCodeLine().getInstruction().getType() == InstructionType.FILLED_NEW_ARRAY) {
                  LOGGER.debug("arrayMode: Found a FILLED_NEW_ARRAY opcode, will handle it.");
                  // parse the involved registers and track them back
                  handleFilledNewArray(bb, fcl.getCodeLine(), fcl.getIndex(), fuzzyLevel, fuzzyLevelOffset, fixedPath, sliceNode, previousRegister);
                }
                else if (fcl.getCodeLine().getInstruction().getType() == InstructionType.INVOKE
                    || fcl.getCodeLine().getInstruction().getType() == InstructionType.INVOKE_STATIC) {
                  // some array is returned from a method
                  LOGGER.debug("arrayMode: Found an INVOKE opcode, will handle it.");
                  // array reg is the currently backtracked register
                  handleInvoke(fcl.getBasicBlock(), fcl.getIndex(), arrayReg, false, fuzzyLevel, fuzzyLevelOffset, fixedPath, sliceNode);
                }
                else {
                  // this is unexpected, what did we find?
                  throw new SyntaxException("arrayMode: Found unexpected opcode in arraymode! cl=" + fcl);
                }
              }

              bbl.removeLastBBFromList(); // we're done for this path
              abort = true;
            }
            break;

          case MOVE:
            // Check if something is moved into the tracked register, if so, track the moved register
            if (Arrays.equals(i.getResultRegister(), arrayReg)) {
              arrayReg = i.getInvolvedRegisters().get(0); // there is only one register
              LOGGER.debug("arrayMode: ArrayReg MOVED, new={}", new String(arrayReg));
              bbl.setNewStateforCurrentBB(arrayReg);
            }

            /*
             * TODO: Let's assume array reg is v50 and we find this:
             * move-object/from16 v0, v50
             * Our array is now also in v0. Should we also track v0 now?
             * If so, we have to do it FORWARDs, not BACKWARDs!
             * Therefore use method forwardFindAPuts(...).
             */
            break;

          case PUT:
            // check if our array is copied to some field and add it to the todolist if this is the case
            if (Arrays.equals(i.getInvolvedRegisters().get(0), arrayReg)) {
              LinkedList<BasicBlock> p = new LinkedList<BasicBlock>(bbl.getPathForLastBB());
              todoList.addArrayFieldToTrack(i.getResultField(), fuzzyLevel, fuzzyLevelOffset, p, sliceNode, previousRegister);
            }
            break;

          default:
            // Check if all other opcodes overwrite our array register, if so, we're screwed, if not, we're fine
            if (cl.isCode() && i.getResultRegister() != null &&
                Arrays.equals(i.getResultRegister(), arrayReg)) {
              if ((i.getType() == InstructionType.CONST) && ("0".equals(i.getConstantValue()) || "0x0".equals(i.getConstantValue()))) {
                // If this happens we assume that the array was initialized with the "null value"
                LOGGER.debug("arrayMode: Found an 0x0 const, array probably NULL'ed. Stopping search.");
                bbl.removeLastBBFromList(); // we are done for this path
                abort = true;
              }
              else if (i.getType() == InstructionType.AGET) {
							/*
							 * Handle special case (multidimensional arrays):
							 * iget-object v0, v0, Lcom/tapjoy/TapjoyVideoObject;->buttonData:[[Ljava/lang/String; <= our multidimensional array v0
							 * const/4 v1, 0x0
							 * aget-object v0, v0, v1 <= Overwriting v0 with an array from an array, this would crash otherwise
							 * const/4 v1, 0x1
							 * aget-object v0, v0, v1 <= Array mode, array is v0
							 * invoke-static {v0}, Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri; <= Tracking v0
							 */
                arrayReg = i.getInvolvedRegisters().get(0); // set the array to the other array (in this case also v0)
                bbl.setNewStateforCurrentBB(arrayReg);
                LOGGER.debug("arrayMode: Multidimensional array GET. Array reg now: {}", new String(arrayReg));
              }
              else {
                LOGGER.error("arrayMode: Found opcode overwriting our array! Aborting, but search continues! {}", cl);
                throw new DetectionLogicError("arrayMode: Found opcode overwriting our array! Aborting, but search continues! " + cl);
              }
            }
            break;
        }
      }
    }
  }

  /**
   * Find all xGET-x which assign an array to a register v. Then search for all APUT's which put
   * something into our array in register v. The put'ed values are then backtracked as a RegisterSearch.
   *
   * @param ctt with ca: c=class, a=arrayname (the field)
   */
  private void findArrayGets(TodoList.ClassContentTracker ctt) {
    LOGGER.debug("findArrayGets, ctt={}", ctt);

    for (SmaliClass sf : app.getAllSmaliClasses()) {
      for (Method m : sf.getMethods()) {
        for (BasicBlock bb : m.getBasicBlocks()) {
          LinkedList<CodeLine> codeLines = bb.getCodeLines();

          for (int i = 0; i < codeLines.size(); i++ ) {
            CodeLine cl = codeLines.get(i);
            Instruction instruction = cl.getInstruction();

            if (instruction.getType() == InstructionType.GET) {
              // either IGET or SGET, check if the loaded field matches our array
              byte[][] instField = Instruction.parseClassAndField(instruction.getInvolvedFields().get(0));

              if (Arrays.equals(ctt.getCi()[0], instField[0]) && Arrays.equals(ctt.getCi()[1], instField[1])) {
								/*
								 * We found an opcode that loads our array of interest, ca, into a register.
								 * Now check if we find any APUTs in this array, do this search forward through the BBs!
								 */
                LOGGER.debug("findArrayGets: Found array-get, cl={}", cl);
                LinkedList<BasicBlock> path = ctt.getPath(); // add BB to the path, search begins at last BB in path
                path.addLast(bb);

                forwardFindAPuts(i, instruction.getResultRegister(), ctt.getFuzzyLevel(), ctt.getFuzzyOffset(), path,
                    ctt.getPreviousSliceNode(), ctt.getPreviousRegister());
              }
            }
          }
        }
      }
    }
  }

  /**
   * We have a BB (which must the last BB in the path), a codeline index and an array register arrayReg to track.
   * Now look at the next lines and see if we find some APUTs which copies something from register v into our
   * array arrayReg. If so, we need to backtrack v.
   *
   * @param codeLineIndex the codeline index where to search from
   * @param arrayReg the array register
   * @param fuzzyLevel
   * @param fuzzyLevelOffset
   * @param path the current path INCLUDING the BB to search in as the last BB
   * (use a new object otherwise things might go boom), path contains bb!
   */
  private void forwardFindAPuts(int codeLineIndex, byte[] arrayReg, int fuzzyLevel, int fuzzyLevelOffset,
                                LinkedList<BasicBlock> path, SliceNode sliceNode, byte[] previousRegister) {
    LOGGER.debug("ForwardFindAPuts: index={}, array reg={}", codeLineIndex, new String(arrayReg));
    BasicBlock bb = path.getLast();
    BasicBlockList bbl = new BasicBlockList(path, arrayReg, false); // it is a forward search

    if (!(bb.getCodeLines().size() > codeLineIndex)) {
			/*
			 * There should be something unless the file is broken! If we end here, something is fishy.
			 * Nevertheless, use the next BBs.
			 */
      LOGGER.error("forwardFindAPuts: CodelineIndex is too big. " + codeLineIndex + ">" + (bb.getCodeLines().size()-1));
      codeLineIndex = 0; // search the new ones from the beginning
    } else {
      codeLineIndex++; // use the next line
    }

    while ((bb = bbl.getNextBb()) != null) { // check all BBs
      for (int i = codeLineIndex; i < bb.getCodeLines().size(); i++) { // check all codelines in the BB
        // TODO: what about MOVE opcodes?
        CodeLine cl = bb.getCodeLines().get(i);
        LOGGER.debug("forwardFindAPuts: cl={}", cl);
        Instruction instruction = cl.getInstruction();
        byte[] targetReg = instruction.getResultRegister();
        if ((!(instruction.getType() == InstructionType.APUT)) && Arrays.equals(arrayReg, targetReg)) {
          // something overwrote our array register: we're done with this path.
          bbl.removeLastBBFromList();
          break;
        }
        else if ((instruction.getType() == InstructionType.APUT) && Arrays.equals(arrayReg, targetReg)) {
          // we found an APUT and it copies into our array (register)
          byte[] regCopiedIntoArray = instruction.getInvolvedRegisters().get(0);
          LOGGER.debug("forwardFindAPuts: Found an APUT for our array, backtracking reg={}", new String(regCopiedIntoArray));
          // backtracking register later
          TodoList.RegisterSearch rs = new TodoList.RegisterSearch(regCopiedIntoArray, bb, i, fuzzyLevel,
              fuzzyLevelOffset, bbl.getPathForLastBB(), sliceNode, previousRegister); // bb will later be added to the path
          todoList.addRegisterToTrack(rs);
        }
        /*else {
          // some unrelated opcode
          continue;
        }*/
      }
      codeLineIndex = 0; // reset index for the next BB if there is any
    }
  }

  /**
   * We have a BB (which must be the last BB in the path), a codeline index and an array register
   * (arrayReg) to track. Now look at the previous opcodes and see if we find some APUTs which
   * copy something from register v into arrayReg. If so, we need to backtrack v.
   * We stop when something overwrites our arrayReg.
   *
   * This is only relevant for the results in textual output form.
   *
   * @param codeLineIndex the codeline index in the BB
   * @param arrayReg the array register to track
   * @param fuzzyLevel is the search fuzzy (inaccurate)?
   * @param fuzzyLevelOffset
   * @param path the current path INCLUDING the BB to search in as the last BB (use a new object otherwise things might go boom), path contains bb!
   * @throws SyntaxException
   * @throws DetectionLogicError
   */
  private void backwardFindAPuts(int codeLineIndex, byte[] arrayReg, int fuzzyLevel, int fuzzyLevelOffset,
                                 LinkedList<BasicBlock> path, SliceNode sliceNode, byte[] previousRegister) throws SyntaxException, DetectionLogicError {
    LOGGER.debug("BackwardFindAPuts: index={}, arrayReg={}", codeLineIndex, new String(arrayReg));

    boolean firstRun = true;
    BasicBlock bb;

    BasicBlockList bbl = new BasicBlockList(path, arrayReg); // backward search
    while ((bb = bbl.getNextBb()) != null) {
      if (!firstRun)
        codeLineIndex = bb.getCodeLines().size()-1; // for new BBs begin at the end of the BB
      firstRun = false;

      for (int i = codeLineIndex; i >= 0; i--) { // check all codelines in the BB
        CodeLine cl = bb.getCodeLines().get(i);
        LOGGER.debug("backwardFindAPuts: Handling cl={}", cl);
        Instruction instruction = cl.getInstruction();
        byte[] targetReg = instruction.getResultRegister();

        if ((instruction.getType() == InstructionType.APUT) && Arrays.equals(arrayReg, targetReg)) {
          // We found an APUT and it copies into our array (register)
          byte[] regCopiedIntoArray = instruction.getInvolvedRegisters().get(0);
          LOGGER.debug("backwardFindAPuts: Found an APUT for our array, backtracking reg={}", new String(regCopiedIntoArray));
          // Backtracking register later
          TodoList.RegisterSearch rs = new TodoList.RegisterSearch(regCopiedIntoArray, bb, i, fuzzyLevel,
              fuzzyLevelOffset, bbl.getPathForLastBB(), sliceNode, previousRegister);
          todoList.addRegisterToTrack(rs);
        }
        else if (instruction.getType() == InstructionType.FILL_ARRAY_DATA && Arrays.equals(arrayReg, targetReg)) { // array initialization
          Constant c = new Constant(cl, fuzzyLevel, bbl.getPathForLastBB(), searchId);
          LOGGER.debug("backwardFindAPuts: Found constant. c={}", c);
          currentSliceTree.addConstant(c, bb, sliceNode, previousRegister);
          criterion.addFoundConstant(searchId, c);
          return;
        }
        else if (instruction.getType() == InstructionType.NEW_ARRAY && Arrays.equals(arrayReg, targetReg)) { // array creation
					/*	It might be something like this:
					 *  const/4 v0, 0x3
					 *  new-array v0, v0, [I							  <-- found
					 *  sput-object v0, Ltest/android/Testcase5;->a1:[I   <-- started
					 *  Java code: private static final int[] a1 = { 0, 0, 0 };
					 */
          LOGGER.debug("backwardFindAPuts: Lost track (new-array). The register is overwritten.");
          return;
        }
        else if ((!(instruction.getType() == InstructionType.APUT)) && Arrays.equals(arrayReg, targetReg)) {
          // Something overwrote our array register: we are done.
          LOGGER.debug("backwardFindAPuts: ArrayReg overwritten. Done.");
          return;
        }
        else if ((instruction.getType() == InstructionType.MOVE) && Arrays.equals(arrayReg, targetReg)) {
          LOGGER.debug("backwardFindAPuts: ArrayReg moved, old={}, new={}", new String(arrayReg), new String(instruction.getInvolvedRegisters().get(0)));
          arrayReg = instruction.getInvolvedRegisters().get(0);
        } else {
          // some unrelated opcode
          LOGGER.trace("backwardFindAPuts: unrelated cl.");
        }
      }
    }
  }

  /**
   * Find all xPUT-x opcodes which assign an array in a register av to our array field ca.
   * We therefore search for opcodes which actually store an array in our array field ca.
   * If we find such an PUT, we search for APUTs from this position which actually put some
   * values in the register av where the array is assigned to. The putted values/registers are then further
   * backtracked with a RegisterSearch. This search ends if we find a NEW_ARRAY opcode which overwrites our
   * array register av or something overwrites av.
   *
   * @param ctt class content tracker
   * @throws SyntaxException
   * @throws DetectionLogicError
   */
  private void findArrayPuts(TodoList.ClassContentTracker ctt) throws SyntaxException, DetectionLogicError {
    LOGGER.debug("findArrayPuts, ctt={}", ctt);

    for (SmaliClass sf : app.getAllSmaliClasses()) { // search through all SmaliClasses, Methods and BBs
      for (Method m : sf.getMethods()) {
        for (BasicBlock bb : m.getBasicBlocks()) {
          LinkedList<CodeLine> codeLines = bb.getCodeLines();

          for (int i = 0; i < codeLines.size(); i++) {
            CodeLine cl = codeLines.get(i);
            Instruction instruction = cl.getInstruction();

            if (instruction.getType() == InstructionType.PUT) {
              // Either iGET or sGET. Check if the field which gets assigned is our searched array
              byte[][] fieldName = instruction.getResultField();
              if (Arrays.equals(ctt.getCi()[0], fieldName[0]) && Arrays.equals(ctt.getCi()[1], fieldName[1])) {
								/*
								 * We found an opcode that stores our array of interest, ca, into a field.
								 * Now check if we find any APUTs in this array, do this search backwards through the BBs!
								 */
                byte[] arrayReg = instruction.getInvolvedRegisters().get(0); // this is our array!
                // Search the previous opcodes
                LinkedList<BasicBlock> path = ctt.getPath();
                path.addLast(bb);

                backwardFindAPuts(i, arrayReg, ctt.getFuzzyLevel(), ctt.getFuzzyOffset(), path, ctt.getPreviousSliceNode(), ctt.getPreviousRegister());
								/*
								 * Also look at the following opcodes and check if our array register gets overwritten. It is possible
								 * to first create an array, assign it to a field, and put values into the array "directly through
								 * the local array object".
								 */
                LinkedList<BasicBlock> path2 = new LinkedList<BasicBlock>(path); // we need a copy
                path2.add(bb);

                forwardFindAPuts(i, arrayReg, ctt.getFuzzyLevel(), ctt.getFuzzyOffset(), path2, ctt.getPreviousSliceNode(), ctt.getPreviousRegister());
              }
            }
          }
        }
      }
    }
  }

  /**
   * Handle an INVOKE opcode. This method will attempt to access the invoked method.
   * It is only able to do so if the method is somewhere in a SMALI file within the analyzed application.
   *
   * If the method is known (= SMALI file available), all return values are eventually later backtracked and
   * eventually put into the ResultList. Then, all method parameters (registers) are backtracked.
   *
   * If the method is unknown, only the parameters are backtracked.
   * This enabled us to, eg. see Strings which are added to a StringBuilder with its append() method.
   *
   * @param bb the BasicBlock where the INVOKE opcode comes from
   * @param register the currently backtracked register
   * @param index the index of the invoke opcode within this BB
   * @param resultWasMoved true if the result was moved to the backtracked register, this will trigger the search for return values in the invoked method
   * @param fuzzyLevel
   * @param fuzzyLevelOffset
   * @param path the path (passed through)
   * @throws DetectionLogicError
   */
  private void handleInvoke(BasicBlock bb, int index, byte[] register, boolean resultWasMoved, int fuzzyLevel,
                            int fuzzyLevelOffset, LinkedList<BasicBlock> path, SliceNode sliceNode) throws DetectionLogicError {
    CodeLine cl = bb.getCodeLines().get(index);

    // Verify that the codeline instruction is indeed an INVOKE
    if (!(cl.getInstruction().getType() == InstructionType.INVOKE
        || cl.getInstruction().getType() == InstructionType.INVOKE_STATIC)) {
      throw new DetectionLogicError("Wrong instruction, need INVOKE, but got: " + cl);
    }

    // Check if the invoked method is available within the application scope
    boolean methodKnown = true;
    byte[][] cmp2 = cl.getInstruction().getCalledClassAndMethodWithParameter();
    String cmp2Class = new String(cmp2[0]);
    String cmp2Method = new String(cmp2[1]);
    String cmp2Parameters = new String(cmp2[2]);
    try {
      app.getMethodByClassAndName(cmp2Class, cmp2Method, cmp2[2], cmp2[3]);
    } catch (ClassOrMethodNotFoundException e) {
      LOGGER.debug("handleInvoke: Unable to backtrack into method, will parse parameters only. {}", e.getMessage());
      methodKnown = false;
    }

    // If the result was moved to the tracked register and the method is known, the return values are backtracked later
    if (methodKnown && resultWasMoved) {
      LOGGER.debug("handleInvoke: Will later backtrack RETURN values from {}.{}({})", cmp2Class,
          cmp2Method, new String(cmp2[2]));

      // If the invoke statement is actually an interface, search for implementors
      String opCode = new String(cl.getInstruction().getOpCode());
      if (opCode.equals("invoke-interface") || opCode.equals("invoke-interface/range")) {
        List<SmaliClass> smaliClasses = app.getAllSmaliClasses();
        for (SmaliClass smaliClass : smaliClasses) {
          for (String implInterface : smaliClass.getImplementedInterfaces()) {
            if (implInterface.equals(cmp2Class)) {
              LOGGER.debug("handleInvoke: Class {} implements interface {}", smaliClass.getFullClassName(false), cmp2Class);
              cmp2[0] = smaliClass.getFullClassName(false).getBytes();
              todoList.addReturnValuesFromMethod(cmp2, fuzzyLevel, fuzzyLevelOffset, path, sliceNode, register);
            }
          }
        }
      } else {
        // Search for all returns in this method if it is known
        todoList.addReturnValuesFromMethod(cmp2, fuzzyLevel, fuzzyLevelOffset, path, sliceNode, register);
      }
    } else { // if (resultWasMoved) {
      // Don't add clone() calls as constants, e.g. byte[] a = {1,2,3}. a.clone();
      // Also don't add constants for selected other nodes
      if (cmp2Method.equals("clone") && cmp2Class.matches("[VZBSCIJFD]") && new String(cmp2[3]).equals("Ljava/lang/Object;")) {
        LOGGER.debug("handleInvoke: Found a clone() call onto a {} object", cmp2Class);
      } else if (cmp2Class.equals("java/util/Arrays") && cmp2Method.equals("copyOf")) {
        LOGGER.debug("handleInvoke: Found Arrays->copyOf");
      } else if (cmp2Class.equals("java/net/URLEncoder") && cmp2Method.equals("encode")) {
        LOGGER.debug("handleInvoke: Found URLEncoder->encode");
      } else {
        // Mark the method as constant because it is not known/slicable.
        try {
          LOGGER.debug("handleInvoke: Adding constant for cl = {}", cl);
          Constant c = new Constant(cl, fuzzyLevel, path, searchId);
          currentSliceTree.addConstant(c, bb, sliceNode, register);
          criterion.addFoundConstant(searchId, c);
        } catch (SyntaxException e) {
          LOGGER.error("handleInvoke: Could not add found method to found constants", e);
          criterion.logException(e);
        }
      }
    }

		/*
		 * Backtrack all parameters of the invoked method.
		 * This will result in a fuzzy search because we do not really know what the parameters
		 * are and where they are used. Do not backtrack the actual backtracked register (again).
		 */
    boolean increaseFuzzyness;
    for (int regIndex = 0; regIndex < cl.getInstruction().getInvolvedRegisters().size(); regIndex++) {
      increaseFuzzyness = true;
      byte[] reg = cl.getInstruction().getInvolvedRegisters().get(regIndex);

      if (regIndex == 0 && !(cl.getInstruction().getType() == InstructionType.INVOKE_STATIC)) {
				/*
				 * Skip the first parameter for non-static invokes if it references the class object ("this").
				 * Normally, this is register p0. Non-static invokes always have the first register referencing
				 * the object where the method gets invoked, which might be "this". If we backtrack "this", this
				 * could result in a huge "overtracking"!
				 *
				 * But we want to track the first parameter if it refers to a non-static object, eg.:
				 * const-string v2, "some string"
				 * invoke-virtual {v1, v2}, Ljava/lang/StringBuffer;->append(Ljava/lang/String;)Ljava/lang/StringBuffer;
				 * invoke-virtual {v1}, Ljava/lang/StringBuffer;->toString()Ljava/lang/String; <-- WE WANT TO TRACK V1
				 * move-result-object v0  <-- v0 IS BACKTRACKED
				 *
				 * In any case the problem remains that p0 might be overwritten and will then not reference "this" anymore.
				 * However, we simply ignore this here because otherwise we would have to search all previous opcodes if
				 * they overwrite p0.
				 *
				 * So for non-static invokes we ignore the first parameter/register if it is p0, otherwise we track it.
				 * Static invokes are not affected by this search anyway.
				 */
        if (!bb.getMethod().isStatic() && Arrays.equals(reg, P0_THIS)) continue;
        else {
					/*
					 * Do not increment it for v1 in the example above, otherwise v2 would be tagged with a value of +2,
					 * which is wrong. It should be tagged with +1, because v2 is added to v1, and v1 is just a reference to
					 * some "intermediate object". This check is only performed for the first register for non-static
					 * invokes. All other found registers which are backtracked get their fuzzyness increased.
					 */
          increaseFuzzyness = false;
        }
      }

      if (!resultWasMoved && Arrays.equals(reg, register)) {
				/*
				 * Skip the register which is currently backtracked but only do it if the result was not moved.
				 * If it was moved, eg. StringBuilder.toString() we still need to track the StringBuilder object.
				 * But if it was not moved, the search for this register will end (the calling method will
				 * immediately return, hence we need a new RegisterSearch for it!
				 */
        continue;
      } else { // resultWasMoved
        // Whitelist
        if (cmp2Class.equals("java/lang/String") && cmp2Method.equals("getBytes") && !cmp2Parameters.isEmpty()) {
          // Skip charsetName in String.getBytes(String charsetName)
          if (regIndex == 1) { // 0 == object instance, 1 == charsetName
            continue;
          }
        } else if (cmp2Class.equals("java/lang/String") && cmp2Method.equals("<init>") &&
            (cmp2Parameters.equals("[BLjava/lang/String;")) || (cmp2Parameters.equals("[BIILjava/lang/String;"))) {
          // Skip charsetName in
          // String(byte[] bytes, String charsetName) and
          // String(byte[] bytes, int offset, int length, String charsetName)
          if (regIndex == (cl.getInstruction().getInvolvedRegisters().size() - 1)) {
            continue;
          }
        } else if (cmp2Class.equals("java/net/URLEncoder") && cmp2Method.equals("encode")) {
          // Skip enc (= encoding charset) in URLEncoder.encode(String s, String enc)
          if (regIndex == 1) { // 0 == string s, 1 == string enc (because of the static call => no instance register)
            continue;
          }
        } else if (cmp2Class.equals("java/security/MessageDigest") && cmp2Method.equals("getInstance")) {
          // Skip algorithm and provider in
          // MessageDigest.getInstance(String algorithm)
          // MessageDigest.getInstance(String algorithm, String provider)
          // MessageDigest.getInstance(String algorithm, Provider provider)
          continue;
        } else if (cmp2Class.equals("java/util/Arrays") && cmp2Method.equals("copyOf")) {
          // Skip newLength in Arrays.copyOf(boolean[] original, int newLength)
          if (regIndex == 1) { // 1 => because of the static call without preceding instance reg.
            continue;
          }
        } else if (cmp2Class.equals("javax/crypto/SecretKeyFactory") && cmp2Method.equals("getInstance")) {
          // Skip algorithm and provider in
          // SecretKeyFactory.getInstance(String algorithm)
          // SecretKeyFactory.getInstance(String algorithm, String provider)
          // SecretKeyFactory.getInstance(String algorithm, Provider provider)
          continue;
        } else if (cmp2Class.equals("javax/crypto/Mac") && cmp2Method.equals("getInstance")) {
          // Skip algorithm and provider in
          // Mac.getInstance(String algorithm)
          // Mac.getInstance(String algorithm, String provider)
          // Mac.getInstance(String algorithm, Provider provider)
          continue;
        }
      }

      LOGGER.debug("handleInvoke: Adding parameterIndex/register: {}/{}", regIndex, new String(reg));

      int fl = fuzzyLevel;
      if (increaseFuzzyness)
        fl = fuzzyLevel+1;

      // This search is fuzzy if the register does not only reference an "intermediate object" (see fl variable).
      TodoList.RegisterSearch rs2 = new TodoList.RegisterSearch(reg, bb, index, fl, fuzzyLevelOffset, path, sliceNode, register);
      todoList.addRegisterToTrack(rs2);
    }
  }

  /**
   * Parse the involved registers in an FILLED_NEW_ARRAY and track them back.
   *
   * @param bb the basic block where the codeline is taken from
   * @param cl the codeline with the FILLED_NEW_ARRAY
   * @param index the index of the cl in the bb
   * @param fuzzyLevel
   * @param fuzzyLevelOffset
   * @param path the path (passed through)
   * @throws DetectionLogicError if the opcode in cl is not of type FILLED_NEW_ARRAY
   */
  private void handleFilledNewArray(BasicBlock bb, CodeLine cl, int index, int fuzzyLevel,
                                    int fuzzyLevelOffset, LinkedList<BasicBlock> path, SliceNode sliceNode,
                                    byte[] previousRegister) throws DetectionLogicError {
    if (cl.getInstruction().getType() != InstructionType.FILLED_NEW_ARRAY)
      throw new DetectionLogicError("Expected FILLED_NEW_ARRAY opcode, but code cl=" + cl);

    // Parse the involved registers and track them back
    for (byte[] register : cl.getInstruction().getInvolvedRegisters()) {
      TodoList.RegisterSearch rs = new TodoList.RegisterSearch(register, bb, index, fuzzyLevel, fuzzyLevelOffset, path, sliceNode, previousRegister);
      todoList.addRegisterToTrack(rs);
    }
  }

  public List<CodeLine> findInvokes(byte[][] cmp, byte[][] startMethod, int parameterIndex) throws DetectionLogicError {
    List<TodoList.RegisterSearch> invokes = findInvokes(cmp, startMethod, parameterIndex, 0, new LinkedList<BasicBlock>(), null, null);

    List<CodeLine> codeLines = new ArrayList<>(invokes.size());
    for (TodoList.RegisterSearch rs : invokes) {
      codeLines.add(rs.getBB().getCodeLines().get(rs.getIndex()));
    }

    return codeLines;
  }

  /**
   * Find all invokes in all files and return all corresponding RegisterSearch objects in a list.
   * This method automatically handles static invokes.
   *
   * @param cmp the class, method and its parameters, the class cmp[0] may be the wildcard '*'.
   * @param parameterIndex the parameter index to track
   * @param fuzzyLevel
   * @param path the path
   * @throws DetectionLogicError
   * @return the list of found invokes
   */
  private List<TodoList.RegisterSearch> findInvokes(byte[][] cmp, byte[][] startMethod, int parameterIndex,
                                                    int fuzzyLevel, LinkedList<BasicBlock> path, SliceNode sliceNode,
                                                    byte[] previousRegister) throws DetectionLogicError {
    List<TodoList.RegisterSearch> rsList = new ArrayList<>();

    List<File> smaliClassFiles = new ArrayList<File>();
    if (startMethod != null && startMethod[0] != null) {
      smaliClassFiles.add(new File(app.getSmaliDirectory(), new String(startMethod[0]) + FileList.SMALI_FILES));
    } else {
      smaliClassFiles = app.getAllRawSmaliFiles();
    }

    for (File rawFile : smaliClassFiles) {
      SmaliClass smaliClass = app.getSmaliClass(rawFile);
      if (smaliClass == null) {
        LOGGER.error("Could not find SMALI file for raw file '{}'. SmaliClass object most probably threw an" +
            "exception while parsing it. Ignoring this one.", rawFile);
        continue;
      }

      List<Method> methods = new LinkedList<>();
      if (startMethod != null && startMethod[1] != null) {
        Method method = smaliClass.getMethodByName(new String(startMethod[1]));
        if (method != null) {
          methods.add(method);
        }
      } else {
        methods = smaliClass.getMethods();
      }

      for (Method m : methods) {
        //LOGGER.debug("Looking in method: " + rawFile.getName() + "." + m.getName() + "()");
        for (BasicBlock bb : m.getBasicBlocks()) {
          for (CodeLine cl : bb.getCodeLines()) {
            Instruction i = cl.getInstruction();

            // Search for the actual invoke instruction
            if (i.getType() == InstructionType.INVOKE || i.getType() == InstructionType.INVOKE_STATIC) {
              if ( (Arrays.equals(cmp[0], WILDCARD) || Arrays.equals(i.getCalledClassAndMethodWithParameter()[0], cmp[0]))
                  && Arrays.equals(i.getCalledClassAndMethodWithParameter()[1], cmp[1])
                  && (cmp[2] == null || Arrays.equals(i.getCalledClassAndMethodWithParameter()[2], cmp[2])) ) {
                // Found a method with correct invoke
                // invoke-direct {v0}, Landroid/content/IntentFilter;-><init>()V
                LOGGER.debug("Method {}->{} invokes {}->{}({}) on line {}", smaliClass.getFullClassName(true),
                    m.getName(), new String(cmp[0]), new String(cmp[1]),
                    new String(i.getCalledClassAndMethodWithParameter()[2]), cl.getLineNr());

                // Check for a static invoke
                int realParameterIndex = parameterIndex;
                if (i.getType() == InstructionType.INVOKE_STATIC) {
                  LOGGER.debug(" Invoke is static");
                } else {
                  // Raise the parameterIndex if not in a static class because then p0 = this reference
                  realParameterIndex++;
                }

                List<byte[]> regs = i.getInvolvedRegisters();
                // If no detailed method signature is given, check the parameter index though
                if (cmp[2] == null && realParameterIndex >= regs.size()) {
                  // This will not work, we skip this invoke. It is always better to define the method signature.
                  LOGGER.error("Can not backtrack parameterIndex {} - out of range! No method signature defined. cl={}", realParameterIndex, cl);
                  continue;
                } else if (realParameterIndex >= regs.size() || realParameterIndex < 0) {
                  // This should not happen!
                  throw new DetectionLogicError("Can not backtrack parameterIndex " + realParameterIndex + " - out of range! cl=" + cl);
                }

                byte[] register = regs.get(realParameterIndex);
                int index = bb.getCodeLines().indexOf(cl);

                TodoList.RegisterSearch rs = new TodoList.RegisterSearch(register, bb, index, fuzzyLevel, 0, path, sliceNode, previousRegister);
                rsList.add(rs);
              }
              // else: Invoke did not match.
            }
          }
        }
      }
    }

    return rsList;
  }

  private List<TodoList.RegisterSearch> findInvokeInCodeLine(CodeLine cl, byte[][] cmp, int parameterIndex, int fuzzyLevel,
                                                    LinkedList<BasicBlock> path, SliceNode sliceNode,
                                                    byte[] previousRegister) throws DetectionLogicError {
    List<TodoList.RegisterSearch> rsList = new ArrayList<>();

    BasicBlock codeLineBB = null;
    for (BasicBlock bb : cl.getMethod().getBasicBlocks()) {
      if (bb.getCodeLines().contains(cl)) {
        codeLineBB = bb;
        break;
      }
    }

    if (codeLineBB == null) {
      throw new DetectionLogicError("BB of code line " + cl + " not found!");
    }

    Instruction i = cl.getInstruction();

    // Search for the actual invoke instruction
    if (i.getType() == InstructionType.INVOKE || i.getType() == InstructionType.INVOKE_STATIC) {
      if ( (Arrays.equals(cmp[0], WILDCARD) || Arrays.equals(i.getCalledClassAndMethodWithParameter()[0], cmp[0]))
          && Arrays.equals(i.getCalledClassAndMethodWithParameter()[1], cmp[1])
          && (cmp[2] == null || Arrays.equals(i.getCalledClassAndMethodWithParameter()[2], cmp[2])) ) {
        // Found a method with correct invoke
        // invoke-direct {v0}, Landroid/content/IntentFilter;-><init>()V
        LOGGER.debug("Method {}->{} invokes {}->{}({}) on line {}", cl.getSmaliClass().getFullClassName(true),
            cl.getMethod().getName(), new String(cmp[0]), new String(cmp[1]),
            new String(i.getCalledClassAndMethodWithParameter()[2]), cl.getLineNr());

        // Check for a static invoke
        int realParameterIndex = parameterIndex;
        if (i.getType() == InstructionType.INVOKE_STATIC) {
          LOGGER.debug(" Invoke is static");
        } else {
          // Raise the parameterIndex if not in a static class because then p0 = this reference
          realParameterIndex++;
        }

        List<byte[]> regs = i.getInvolvedRegisters();
        // If no detailed method signature is given, check the parameter index though
        if (cmp[2] == null && realParameterIndex >= regs.size()) {
          // This will not work, we skip this invoke. It is always better to define the method signature.
          LOGGER.error("Can not backtrack parameterIndex {} - out of range! No method signature defined. cl={}", realParameterIndex, cl);
          return rsList;
        } else if (realParameterIndex >= regs.size() || realParameterIndex < 0) {
          // This should not happen!
          throw new DetectionLogicError("Can not backtrack parameterIndex " + realParameterIndex + " - out of range! cl=" + cl);
        }

        byte[] register = regs.get(realParameterIndex);
        int index = codeLineBB.getCodeLines().indexOf(cl);

        TodoList.RegisterSearch rs = new TodoList.RegisterSearch(register, codeLineBB, index, fuzzyLevel, 0, path, sliceNode, previousRegister);
        rsList.add(rs);
      }
      // else: Invoke did not match.
    }

    return rsList;
  }
}
