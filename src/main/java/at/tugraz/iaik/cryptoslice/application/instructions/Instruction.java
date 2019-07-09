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
package at.tugraz.iaik.cryptoslice.application.instructions;

import at.tugraz.iaik.cryptoslice.application.CodeLine;
import at.tugraz.iaik.cryptoslice.application.SyntaxException;
import at.tugraz.iaik.cryptoslice.application.methods.BasicBlock;
import at.tugraz.iaik.cryptoslice.utils.ByteUtils;
import com.google.common.primitives.Bytes;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;

public class Instruction {
  private static final Logger LOGGER = LoggerFactory.getLogger(Instruction.class);

  private final CodeLine codeLine;
  private InstructionType type = InstructionType.NOT_YET_PARSED;
  private byte[] opCode = null;

  // The register where the result of the operation is located, may be null.
  private byte[] resultRegister = null;
  /**
   * The field where the result of the operation is located, my be null.
   * The first parameter is class name, the second one the field name.
   */
  private byte[][] resultField = null;
  // The involved registers in this operation, eg, when calling a method.
  private List<byte[]> involvedRegisters = new ArrayList<>();
  // The involved fields in this operation, eg, when copying a variable into a register.
  private List<byte[]> involvedFields = new ArrayList<byte[]>();
  // Denotes whether this Instructions holds a constant
  private boolean hasConstant = false;
  // Denotes the label or some opcode that indicates where to jump to, eg, fill-array-data.
  private byte[] label = null;
  /**
   * The class, method and parameters of invoke opcodes. cmpr[0] is the class,
   * cmpr[1] the method, cmpr[2] the raw parameters and cmpr[3] the return value.
   */
  private byte[][] cmpr = null;
  /**
   * This is the value which gets assigned by the const-x opcodes, the constant which is
   * involved in some binary math opcode or the values during array initialization. May be null.
   */
  private Constant constant = null;

  public Instruction(CodeLine codeLine) {
    this.codeLine = codeLine;

    if (codeLine.isEmpty()) {
      type = InstructionType.EMPTY_LINE;
    } else if (codeLine.startsWith(new byte[]{'.'})) {
      type = InstructionType.SMALI_DOT_COMMENT;
    } else if (codeLine.startsWith(new byte[]{':'})) {
      type = InstructionType.LABEL;
    } else if (codeLine.startsWith(new byte[]{'#'})) {
      type = InstructionType.SMALI_HASH_KEY_COMMENT;
    } else { // a shortcut, opcodes should begin with a lowercase letter
      byte firstByte = codeLine.getLine()[0]; // cannot be empty, see first check
      if (firstByte < 97 || firstByte > 122) { // a and z
        type = InstructionType.UNKNOWN;
      }
    }
  }

  public void parseOpCode() {
    // Let us define the type of the opcode if we do not already know there is no opcode at all
    if (!(type == InstructionType.EMPTY_LINE
        || type == InstructionType.SMALI_DOT_COMMENT
        || type == InstructionType.LABEL
        || type == InstructionType.SMALI_HASH_KEY_COMMENT
        || type == InstructionType.UNKNOWN
        // do not ask the map if we know it does not begin with a lowercase letter
    )) {
      LinkedList<byte[]> split = split(codeLine.getLine());
      opCode = split.getFirst();
      type = InstructionMap.getType(opCode);

      // Now let us parse the opcode if it is a opcode that we know of
      if (!(type == InstructionType.UNKNOWN
          || type == InstructionType.EMPTY_LINE
          || type == InstructionType.SMALI_DOT_COMMENT
          || type == InstructionType.LABEL || type == InstructionType.SMALI_HASH_KEY_COMMENT)) {
        parse(split);
      }
    }
  }

  /**
   * Split a byte[] at ' ' and ',' but do not split between { } and " ".
   * '{', '}', ',' and ' ' inside quotes are ignored.
   *
   * @return the byte arrays between the above signs, but without them!
   */
  public static LinkedList<byte[]> split(byte[] input) {
    LinkedList<byte[]> list = new LinkedList<byte[]>();
    int lastIndex = 0;
    boolean inQuotes = false;
    boolean inBrackets = false;
    boolean copyLastSequence = true;

		/*
		 * skipNextQuote is used for special cases like
		 * .local v15, list:Ljava/util/Map;,"Ljava/util/Map<Ljava/lang/String;Ljava/lang/Object;>;" __ ___
		 * We need to ignore the underlined quotes.
		 */
    boolean skipNextQuote = false;

    for (int i = 0; i < input.length; i++) {
      switch (input[i]) {
        case ' ':
          if (!inQuotes && !inBrackets) { // split it
            if (lastIndex != i)
              list.addLast(ByteUtils.subbytes(input, lastIndex, i));
            lastIndex = i + 1; // do not copy ' ' the next time
          }

          break;
        case ',': // same as ' '
          if (!inQuotes && !inBrackets) { // split it
					/*
					 * Dirty workaround for lines like .local v15,
					 * list:Ljava/util
					 * /Map;,"Ljava/util/Map<Ljava/lang/String;Ljava/lang/Object;>;"
					 * If this is not checked, ___ this would be splitted!, but
					 * the last split should occur before list:Ljave/util....
					 */
            if ((i + 1 < input.length) && input[i + 1] == '"'
                && (i - 1 >= 0) && input[i - 1] == ';') {
              // first checks are for array boundaries
              break; // do not split here
            }
            if (lastIndex != i)
              list.addLast(ByteUtils.subbytes(input, lastIndex, i));
            lastIndex = i + 1; // do not copy ' ' the next time
            if (i == input.length - 1)
              copyLastSequence = false; // reached the end
          }

          break;
        case '{':
          if (!inQuotes && !inBrackets) { // opening {, therefore aggregate
            // everything between, " " should always be previous char
            inBrackets = true;
            lastIndex = i + 1; // do not copy { the next time something
            // is copied
          } else if (!inQuotes && inBrackets) {
            // break, this should not happen?!
            LOGGER.error("Split CL: Found { although another { was found!");
          }
          break;

        case '}':
          if (inBrackets && !inQuotes) { // found closing }
            // copy all except { and }
            list.addLast(ByteUtils.subbytes(input, lastIndex, i));
            lastIndex = i + 1; // do not copy } the next time something
            // is copied
            inBrackets = false;
            if (i == input.length - 1)
              copyLastSequence = false; // reached the end
          } else if (!inBrackets && !inQuotes) {
            // break, this should not happen?!
            LOGGER.error("Split CL: Found } although !inQuotes && !inKlammer");
          }

          break;
        case '"':
				/*
				 * The two IFs are a workaround for lines like
				 * .local v15, list:Ljava/util/Map;,"Ljava/util/Map<Ljava/lang/String;Ljava/lang/Object;>;"
				 * The last split should occur before list:Ljave/util.... See skipNextQuote note.
				 */
          if (skipNextQuote) {
            skipNextQuote = false; // Consider next quote again
            break;
          }

          if (!inBrackets && !inQuotes) { // beginning quotes
            if ((i - 2 >= 0) && input[i - 1] == ',' && input[i - 2] == ';') { // first check is for array boundaries
              skipNextQuote = true;
              break; // do not split here AND ignore next '"'
            }
            lastIndex = i;
            inQuotes = true;
          } else if (!inBrackets && inQuotes) {
            if (input[i - 1] == '\\')
              continue; // ignore, " im String
            else { // quotes end/close
              // copy all except the " at the beginning and end
              list.addLast(ByteUtils.subbytes(input, lastIndex, i + 1));
              lastIndex = i + 1;
              copyLastSequence = false;
              inQuotes = false;
            }
          } else {
            // break, this should not happen?!
            LOGGER.error("Split CL: Found unexpected \"!");
          }
          break;

        default:
          // found a normal sign :)
      }
    }
    // check if >= 0, otherwise the last element was already copied.
    // this is only relevant if the last part is a "xyz"
    if (copyLastSequence) {
      // copy last or only the one element
      list.addLast(ByteUtils.subbytes(input, lastIndex, input.length));
    }
    /* for (byte[] bb : list) {
    System.out.println(" ] = " + new String(bb));
    } */

    return list;
  }

  /**
   * This method sets everything up, it has to be called in the constructor!
   * @ref: http://source.android.com/devices/tech/dalvik/dalvik-bytecode.html
   *
   * @param split
   */
  private void parse(LinkedList<byte[]> split) {
    byte[] opCodeLine = codeLine.getLine();

    switch (type) {
      case AGET:
        /*
         * aget-object v0, v0, v1
         *
         * arrayop vAA, vBB, vCC
         * Load data from array vBB at index vCC into vAA.
         * The array index (vCC) is ignored right now.
         */
        resultRegister = split.get(1); // vA
        involvedRegisters.add(split.get(2)); // vB
        involvedRegisters.add(split.get(3)); // vC
        break;

      case APUT:
        /*
         * aput-object v1, v0, v3
         *
         * arrayop vAA, vBB, vCC
         * Put data from vAA into the array vBB at index vCC
         * The array index (vCC) is ignored right now.
         */
        resultRegister = split.get(2); // vB
        involvedRegisters.add(split.get(1)); // vA
        break;

      case CONST:
        /*
         * const-string v2, ", protocol="
         * const/4 v4, 0x0
         *
         * const vAA, #+BBBBBBBB
         * Move the given literal into the specified register.
         */
        resultRegister = split.get(1); // vA
        hasConstant = true;
        break;

      case FILL_ARRAY_DATA:
        /*
         * byte b[] = {'x', 'y', 'z'}; is as expressed as:
         * fill-array-data v0, :array_0
         * ...
         * :array_0
         * .array-data 0x1
         * 0x78t 0x79t 0x7at
         * .end array-data
         *
         * fill-array-data vAA, +BBBBBBBB
         * Fill the given array vAA with the indicated data from a table at +BBBBBBBB.
         */
        resultRegister = split.get(1);
        label = split.get(2);
        hasConstant = true;
        break;

      case FILLED_NEW_ARRAY:
        /*
         * filled-new-array {vC, vD, vE, vF, vG}, type@BBBB
         * filled-new-array/range {vCCCC .. vNNNN}, type@BBBB
         *
         * Construct an array of the given type and size, filling it with the supplied contents.
         * The constructed array is moved to a register at the subsequent move-result-object instruction.
         */
        involvedRegisters = parseRegisterList(split.get(1));
        break;

      case GET:
        /*
         * iget-object v0, p0, Lcom/javelin/hunt/free/a/c;->b:Ljavax/crypto/Cipher;
         * sget-object v1, Lcom/andiord/SMSOperator;->CONTENT_URI:Landroid/net/Uri;
         *
         * iinstanceop vA, vB, field@CCCC
         * Load data from the field@CCCC, belonging to object vB, into vA.
         *
         * sstaticop vAA, field@BBBB
         * Load data from the static field@BBBB into vAA.
         */
        if (opCodeLine[0] == 'i') { // instance-op
          resultRegister = split.get(1); // vA
          involvedRegisters.add(split.get(2)); // vB
          involvedFields.add(split.get(3));
        } else if (opCodeLine[0] == 's') { // static-op
          resultRegister = split.get(1); // vA
          involvedFields.add(split.get(2)); // field
        }
        break;

      case GOTO:
        /*
         * goto +AA
         * Unconditionally jump to the indicated instruction.
         */
        label = split.getLast();
        break;

      case IGNORE:
        /*
         * throw vAA
         * Throw the exception, indicated in vAA.
         */
        break;

      case INVOKE_STATIC: // same as INVOKE
      case INVOKE:
        /*
         * invoke-virtual/range {v0 .. v5}, Landroid/content/ContentResolver;->query(Landroid/net/Uri;)Landroid/database/Cursor;
         * invoke-interface {v7}, Landroid/database/Cursor;->moveToNext()Z
         * invoke-virtual {v7}, Ljava/io/PrintStream;->println(Ljava/lang/String;)V
         *
         * invoke {vC, vD, vE, vF, vG}, meth@BBBB
         * Call the indicated method. Does not always need to have a subsequent move-result.
         */
        // split: 0=opcode, 1=registers, 2=class->method(types)returnType
        involvedRegisters = parseRegisterList(split.get(1));
        // Now parse the class and the method which is called
        cmpr = parseClassAndMethodAndParameterAndReturnValue(split.getLast());
        break;

      case INTERNAL_SMALI_OPCODE:
        /*
         * If the result register overwrites our tracked register, we have to stop.
         *
         * array-length vA, vB
         * Store in vA the amount of array entries in vB.
         *
         * cmpX vAA, vBB, vCC
         * Perform a comparison of vBB, vCC and save the result in vAA.
         *
         * move-exception vAA
         * vAA is the register in which the exception is caught.
         */
        resultRegister = split.get(1);
        break;

      case JMP:
        /*
         * if-eqz v1, :cond_1e
         * if-nez v0, :cond_0
         *
         * if-test vA, vB, +CCCC
         * Branch to the destination +CCCC if the given two registers' values compare as specified.
         *
         * if-testz vAA, +BBBB
         * Branch to the destination +BBBB if the given register's value compares with 0 as specified.
         */
        involvedRegisters.add(split.get(1)); // vA
        if (split.get(0)[split.get(0).length - 1] != 'z') // if-test
          involvedRegisters.add(split.get(2));

        label = split.getLast();
        break;

      case MATH_1: // operations with only 1 target and 1 source register
        /*
         * long-to-int v2, v2
         * eg.: neg-int, int-to-byte, etc.
         *
         * unop vA, vB
         * Perform the unary operation on vB and save the result in vA.
         *
         * binop/2addr vA, vB
         * Perform the binary operation on the two source registers, saving the result in vA (first source register).
         */
        resultRegister = split.get(1);
        involvedRegisters.add(split.get(2));
        break;

      case MATH_2: // binary operations only on registers
        /*
         * eg.: add-int, or-int, etc.
         *
         * binop vAA, vBB, vCC
         * Perform the binary operation on vBB and vCC and save the result in vAA.
         */
        resultRegister = split.get(1);
        involvedRegisters.add(split.get(2));
        involvedRegisters.add(split.get(3));
        break;

      case MATH_2C: // binary operations on a register and a constant
        /*
         * add-int/lit8 v0, v0, 0x1
         *
         * binop/lit8 vAA, vBB, #+CC
         * binop/lit16 vA, vB, #+CCCC
         * Perform the binary operation on the vB(B) and literal value #+CC(CC) and save the result in vA(A).
         */
        resultRegister = split.get(1);
        involvedRegisters.add(split.get(2));
        hasConstant = true;
        break;

      case MOVE:
        /*
         * move-object vA, vB
         * Move content from vB into vA.
         *
         * move-wide/16 vAAAA, vBBBB
         * vAAAA and vBBBB are pairs but are only written short as vX, which means vX and vX+1.
         * The bytecode interpreter knows that vX and vX+1 are paired and will access them accordingly
         * when eg. a long value is accessed.
         */
        resultRegister = split.get(1); // vA
        involvedRegisters.add(split.get(2)); // vB
        break;

      case MOVE_RESULT:
        /*
         * move-result vAA
         * Move the result of the most recent (preceded) INVOKE or FILLED_NEW_ARRAY instruction to vAA.
         */
        resultRegister = split.get(1);
        break;

      case NEW_ARRAY:
        /*
         * new-array v0, v1, [Ljava/lang/String;
         *
         * new-array vA, vB, type@CCCC
         * Construct a new array of an array type CCCC, size vB and let it reference as vA.and size.
         */
        resultRegister = split.get(1);
        involvedRegisters.add(split.get(2)); // vB
        break;

      case NEW_INSTANCE:
        /*
         * new-instance v2, Ljava/lang/StringBuilder;
         *
         * new-instance vAA, type@BBBB
         * Construct a new instance of the given type and store it in vAA.
         */
        resultRegister = split.get(1);
        break;

      case PUT:
        /*
         * sput v0, Lcom/lohan/crackme1/example;->Counter:I
         * iput-object v0, p0, Lcom/javelin/hunt/free/a/c;->c:Ljavax/crypto/Cipher;
         *
         * iinstanceop vA, vB, field@CCCC
         * Save vA to the field@CCCC, belonging to object vB.
         *
         * sstaticop vAA, field@BBBB
         * Save vAA to the static field@BBBB.
         */
        if (opCodeLine[0] == 'i') { // instance-op
          // vB is the reference to the object of field C
          resultField = parseClassAndField(split.get(3)); // field CCCC
        } else if (opCodeLine[0] == 's') { // static-op
          resultField = parseClassAndField(split.get(2)); // field BBBB
        }
        involvedRegisters.add(split.get(1)); // vA

        break;

      case RETURN:
        /*
         * Return from a method.
         *
         * return-void has no return value -> nothing can be parsed.
         */
        if (!Arrays.equals(split.get(0), "return-void".getBytes()))
          involvedRegisters.add(split.get(1));

        break;

      case SWITCH:
        /*
         * packed-switch vAA, +BBBBBBBB
         * Jump to a new instruction based on the value in vAA, using a table of offsets corresponding to each value
         * in a particular integral range. Fall through to the next instruction if there is no match.
         *
         * sparse-switch vAA, +BBBBBBBB
         * Jump to a new instruction based on the value in the given register, using an ordered table of value-offset
         * pairs, or fall through to the next instruction if there is no match.
         */
        involvedRegisters.add(split.get(1)); // vAA
        label = split.get(2);
        break;

      default:
        LOGGER.debug("Did not parse instruction of type " + type + ": " + new String(opCode));
        break;
    }
  }

  /**
   * Parse something like {v0 .. v5}, {v7} or {v7, v8}.
   * '{' and '}' are optional, but may occur only once and as a pair.
   *
   * @param parameters the byte array as described above
   * @return list with all the registers
   */
  private static List<byte[]> parseRegisterList(byte[] parameters) {
    // LOGGER.trace("parseParameter: '" + new String(parameters) + "'");
    List<byte[]> result = new ArrayList<>();

    if (parameters == null || parameters.length == 0) {
      LOGGER.debug("parseParameter: empty parameters detected.");
      return result;
    } else if (parameters[0] == '{' && parameters[parameters.length - 1] == '}') { // Strip the '{' and '}'
      parameters = ByteUtils.subbytes(parameters, 1, parameters.length - 1);
    }

    int regStartPos = 0;
    boolean registerFound = true;
    for (int i = 0; i < parameters.length; i++) {
      if (registerFound && (parameters[i] == ',' || parameters[i] == ' ')) {
        registerFound = false;
        result.add(ByteUtils.subbytes(parameters, regStartPos, i));
      } else if (!registerFound && (parameters[i] != ' ' && parameters[i] != '.')) {
        registerFound = true;
        regStartPos = i;
      }
    }
    result.add(ByteUtils.subbytes(parameters, regStartPos, parameters.length)); // Copy last (or only one) register

    // Expand range for invoke-kind/range {v1 .. v6}
    if (Bytes.contains(parameters, (byte) '.') && result.size() > 1) {
      byte[] vA = result.get(0);
      byte[] vB = result.get(1);
      result.clear();

      int fromReg = Integer.parseInt(new String(ByteUtils.subbytes(vA, 1)));
      int toReg = Integer.parseInt(new String(ByteUtils.subbytes(vB, 1)));
      String regPrefix = String.valueOf((char)vA[0]);
      while (fromReg <= toReg) {
        result.add((regPrefix + fromReg).getBytes());
        fromReg++;
      }
    }

    return result;
  }

  /**
   * Parse the class and the field from a line like this:
   * Lcom/lohan/crackme1/example;->Counter:I This example returns [com/lohan/crackme1/example, Counter].
   *
   * @param smaliCode see above
   * @return an array with the class being the first element and
   * the fieldname the second one, the type is dropped.
   */
  public static byte[][] parseClassAndField(byte[] smaliCode) {
    byte[][] cf = new byte[2][];
    int classEnd = ByteUtils.indexOf(smaliCode, ';');
    int varName = ByteUtils.indexOf(smaliCode, ':');
    cf[0] = ByteUtils.subbytes(smaliCode, 1, classEnd);
    cf[1] = ByteUtils.subbytes(smaliCode, classEnd + 3, varName);

    return cf;
  }

  /**
   * Parse the class,the method and its parameters from a line like 1)
   * Ljava/io/PrintStream;->println(Ljava/lang/String;)V would return [
   * java/io/PrintStream , println, Ljava/lang/String; ] 2)
   * code=[B->clone()Ljava/lang/Object; would return [ B , clone, '' ]
   *
   * @param smaliCode see above
   * @return an array with the class being the first element,
   * the method the second one and the parameters the third one.
   */
  private static byte[][] parseClassAndMethodAndParameterAndReturnValue(byte[] smaliCode) {
    byte[][] cmpr = new byte[4][];
    int dashPos = ByteUtils.indexOf(smaliCode, '-');
    int classEndOffset = 0;
    if (smaliCode[dashPos - 1] == ';')
      classEndOffset = 1; // if the class it not primitive is terminated
    // with a ';', but we do not want to copy it
    int methodEnd = ByteUtils.indexOf(smaliCode, '(');
    int parametersEnd = ByteUtils.indexOf(smaliCode, ')');
    int offset = 0;

    for (byte b : smaliCode) { // read array dimension: [
      if (b == '[')
        offset++;
      else
        break;
    }

    if (smaliCode[offset] == 'L') {
      offset++; // we have a class an want to also skip the L
    }
    cmpr[0] = ByteUtils.subbytes(smaliCode, offset, dashPos - classEndOffset); // class
    cmpr[1] = ByteUtils.subbytes(smaliCode, dashPos + 2, methodEnd); // method
    cmpr[2] = ByteUtils.subbytes(smaliCode, methodEnd + 1, parametersEnd); // parameters
    cmpr[3] = ByteUtils.subbytes(smaliCode, parametersEnd + 1); // return value

    return cmpr;
  }

  public String getConstantValue() throws SyntaxException {
    if (!hasConstant)
      return null;

    // this is only a temp constant
    Constant c = new Constant(codeLine, -1, new LinkedList<BasicBlock>(), -1);
    return c.getValue();
  }

  public List<byte[]> getInvolvedFields() {
    return involvedFields;
  }

  public List<byte[]> getInvolvedRegisters() {
    return involvedRegisters;
  }

  public InstructionType getType() {
    return type;
  }

  public byte[] getLabel() {
    return label;
  }

  public byte[][] getResultField() {
    return resultField;
  }

  public byte[] getResultRegister() {
    return resultRegister;
  }

  public byte[][] getCalledClassAndMethodWithParameter() {
    return cmpr;
  }

  public String getCalledClassName() {
    String classname = (cmpr == null ? "" : new String(cmpr[0]));

    return classname.substring(classname.lastIndexOf('/') + 1);
  }

  public String getCalledMethod() {
    return (cmpr == null ? "" : new String(cmpr[1]));
  }

  public CodeLine getCodeLine() {
    return codeLine;
  }

  public byte[] getOpCode() {
    return opCode;
  }
}
