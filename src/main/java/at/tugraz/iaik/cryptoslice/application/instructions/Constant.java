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

import at.tugraz.iaik.cryptoslice.analysis.slicing.ResourceUtils;
import at.tugraz.iaik.cryptoslice.application.CodeLine;
import at.tugraz.iaik.cryptoslice.application.Field;
import at.tugraz.iaik.cryptoslice.application.SyntaxException;
import at.tugraz.iaik.cryptoslice.application.methods.BasicBlock;
import at.tugraz.iaik.cryptoslice.application.methods.Method;
import at.tugraz.iaik.cryptoslice.utils.ByteUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * This class describes a constant in SMALI bytecode. It is parsed from the instructions itself.
 * A constant is equal to another constant if both have the same CodeLine.
 */
public class Constant {
  private static final String STRING_DESCRIPTION = "java/lang/String";
  // Pattern to match (negative) hex numbers prefixed with 0x.
  private final static Pattern HEX_PATTERN = Pattern.compile("^-?0x([0-9a-fA-F]+)L?");

  public enum ConstantType {
    ARRAY, // if this is set, all values from an array are aggregated inside one constant
    EXTERNAL_METHOD, // an unknown/external (api) method was invoked and the result was written to the backtracked register, methods will only be threated this way if the search is not fuzzy
    FIELD_CONSTANT, // a normal (class) field
    INTERNAL_BYTECODE_OP, // something unusual, if, eg, some exception got moved to our backtracked register!
    LOCAL_ANONYMOUS_CONSTANT, // some constant which are not assigned to any variable, eg, i = i+1. This may not always be correct.
    LOCAL_VARIABLE, // some variable inside a method
    NATIVE_METHOD,
    MATH_OPCODE_CONSTANT, // some constant inside a math opcode
    UNCALLED_METHOD // a method which is never directly invoked but has parameters linked to a tracked register, eg, android.content.BroadcastReceiver.receive(..). Might also be dead code.
  }

  /**
   * The different primitive types in Java and some "special" types:
   * "String", "Math_OP", "Other_Class" (for classes) and "Unknown".
   */
  public enum Type {
    VOID("void"),
    BOOLEAN("boolean"),
    BYTE("byte"),
    SHORT("short"),
    CHAR("char"),
    INTEGER("int"),
    LONG("long"),
    FLOAT("float"),
    DOUBLE("double"),
    STRING("String"),
    MATH_OP("Math-Operator"), // we do not know the type of the value, at least we do not parse it back!
    UNKNOWN("Unknown"), // if it can somehow not be parsed
    OTHER_CLASS("Other-Class"), // if the type is some non-primitive type, as eg, com/example/Blah
    ARRAY("Array"); // an array of any type

    private final String text;

    private Type(String text) {
      this.text = text;
    }

    @Override
    public String toString() {
      return text;
    }
  }

  /**
   * A small helper enum. Describes what we are searching for.
   */
  private enum MetaDataLine {
    LOCAL(".local ".getBytes()),
    RESTART_LOCAL(".restart local ".getBytes());

    private final byte[] text;

    private MetaDataLine(byte[] text) {
      this.text = text;
    }

    private byte[] lineStartsWith() {
      return text;
    }
  }

  private static class VarType {
    private Type type;
    private String typeDescription; // may be null
    private final int arrayDimension;

    /**
     * Use this constructor from a MATH_2 opcode.
     *
     * @param type
     * @param typeDescription
     */
    private VarType(Type type, String typeDescription) {
      this.type = type;
      this.typeDescription = typeDescription;
      arrayDimension = 0;
    }

    /**
     * Use this constructor to parse a value like "[[[Ljava/lang/String;".
     * The L is crucial, the ; is optional.
     * @param code
     */
    private VarType(byte[] code) {
      // sanity check
      if (code == null || code.length == 0) {
        type = Type.UNKNOWN;
        typeDescription = null;
        arrayDimension = 0;
        return;
      }

      // get the array dimension
      int ad = 0;
      for (byte bb : code) {
        if (bb == '[') ad++;
      }
      arrayDimension = ad;

      // parse the type
      byte b = code[arrayDimension]; // for each dimension a [ is prefixed
      switch (b) {
        case 'V':
          type = Type.VOID;
          break;
        case 'Z':
          type = Type.BOOLEAN;
          break;
        case 'B':
          type = Type.BYTE;
          break;
        case 'S':
          type = Type.SHORT;
          break;
        case 'C':
          type = Type.CHAR;
          break;
        case 'I':
          type = Type.INTEGER;
          break;
        case 'J':
          type = Type.LONG;
          break;
        case 'F':
          type = Type.FLOAT;
          break;
        case 'D':
          type = Type.DOUBLE;
          break;
        case 'L':
          type = Type.OTHER_CLASS;
          break;
        default:
          // we could not parse it...
          type = Type.UNKNOWN;
      }

      // parse the non-primitive type
      if (type == Type.OTHER_CLASS) {
        // code looks like this [[[Ljava/lang/String; We do not want the [, L and the terminating ;
        int endOffset = 0; // check if it ends with ; (this depends on the input whether it was already removed
        if (code[code.length-1] == ';')
          endOffset = 1;

        typeDescription = new String(ByteUtils.subbytes(code, arrayDimension+1, code.length-endOffset));
        if (STRING_DESCRIPTION.equals(typeDescription))
          type = Type.STRING;
      } else if (ad > 0) {
        /*
         * Fix the type and description for arrays.
         * Type will be Type.Array and description
         * will be, eg, int[] or some/Class[][].
         */
        StringBuilder sb = new StringBuilder();
        sb.append(type);
        for (int i = 0; i < arrayDimension; i++)
          sb.append("[]");
        typeDescription = sb.toString();
        type = Type.ARRAY;
      } else {
        typeDescription = null;
      }
    }

    public int getArrayDimension() {
      return arrayDimension;
    }

    private Type getType() {
      return type;
    }

    /**
     * Returns the full class name or a description for primitive types
     * @return
     */
    private String getTypeDescription() {
      if (typeDescription != null)
        return typeDescription;

      return type.toString();
    }

    /**
     * Use this method to manually overwrite the type description.
     * @param typeDescription
     */
    private void setTypeDescription(String typeDescription) {
      this.typeDescription = typeDescription;
    }

    @Override
    public String toString() {
      StringBuilder sb = new StringBuilder();
      sb.append(type);
      for (int i = 0; i < arrayDimension; i++) {
        final String s = "[]";
        sb.append(s);
      }

      return sb.toString();
    }
  }

  private static final Logger LOGGER = LoggerFactory.getLogger(Constant.class);

  private final CodeLine cl;
  private int fuzzyLevel;
  private final LinkedList<BasicBlock> path;
  private final int searchId;

  private final ConstantType constantType;
  private final String identifier;
  private String value;
  private String unparsedValue;
  private VarType varType;

  /**
   * Create a new constant. This constructor will not parse the CodeLine but will set the provided type and
   * value. This way, one can create arbitrary "constant-types" which do not really relate to some CodeLine
   * or where one CodeLine is not enough to predict a correct value.
   *
   * @param cl the CodeLine
   * @param fuzzyLevel set this to >0 if this Constant was found in an inaccurate fuzzy search
   * @param path the path the Slicer took to find this constant. It is saved to a new object and the given reference may be reused
   * @param searchId an Id which all Constants should have in common which were found during one run of the Slicer for one tracked invoke
   * @param constantType the type of the constant
   * @param value the freely chosen value
   */
  public Constant(CodeLine cl, int fuzzyLevel, LinkedList<BasicBlock> path, int searchId, ConstantType constantType, String value) {
    this.cl = cl;
    this.fuzzyLevel = fuzzyLevel;
    this.path = new LinkedList<BasicBlock>(path);
    this.searchId = searchId;
    this.constantType = constantType;
    this.value = value;
    this.varType = new VarType(null);
    this.identifier = null;
  }

  public Constant(CodeLine cl, int fuzzyLevel, LinkedList<BasicBlock> path, int searchId) throws SyntaxException {
    this(cl, fuzzyLevel, path, searchId, null);
  }

  /**
   * Parse the constant from one CodeLine. Additional information is retrieved from nearby SMALI .local or .restart local lines
   * if they are available.
   *
   * @param cl the CodeLine to parse
   * @param fuzzyLevel set this to >0 if this Constant was found in an inaccurate fuzzy search
   * @param path the path the Slicer took to find this constant. It is saved to a new object and the given reference may be reused
   * @param searchId an Id which all Constants should have in common which were found during one run of the Slicer for one tracked invoke
   * @throws SyntaxException if something goes wrong
   */
  public Constant(CodeLine cl, int fuzzyLevel, LinkedList<BasicBlock> path, int searchId, ConstantType constType) throws SyntaxException {
    this.cl = cl;
    this.fuzzyLevel = fuzzyLevel;
    this.path = new LinkedList<BasicBlock>(path);
    this.searchId = searchId;

    if (cl.startsWith(Field.FIELD)) {
      constantType = ConstantType.FIELD_CONSTANT;

      // Parse name
      int colonIndex = ByteUtils.indexOf(cl.getLine(), ':');
      int spaceBeforeColonPos = ByteUtils.indexOfReverse(cl.getLine(), ' ', colonIndex);
      identifier = new String(ByteUtils.subbytes(cl.getLine(), spaceBeforeColonPos+1, colonIndex));

      /*
       * Parse type and value
       * Syntax: http://code.google.com/p/smali/wiki/TypesMethodsAndFields
       */
      int equalSignIndex = ByteUtils.indexOf(cl.getLine(), '='); // backward/reverse search not possible b/c the value might be a String containing =
      if (equalSignIndex < 0) {
        // no value, eg: .field private name:I
        value = null;
        varType = new VarType(ByteUtils.subbytes(cl.getLine(), colonIndex+1));
      } else {
        // eg: .field private static final name:J = 0x1L
        varType = new VarType(ByteUtils.subbytes(cl.getLine(), colonIndex + 1, equalSignIndex - 1));
        unparsedValue = new String(ByteUtils.subbytes(cl.getLine(), equalSignIndex + 2));
        value = parseConstant(varType.getType(), unparsedValue);

        // Found a resource ID -> try to resolve the related resource value (only String)
        if (cl.getSmaliClass().getFullClassName(false).endsWith("R$string") && varType.getType() == Type.INTEGER) {
          File bytecodeDir = cl.getSmaliClass().getApplication().getBytecodeDecompiledDirectory();
          String resVal = ResourceUtils.findStringValueForResourceName(bytecodeDir, identifier);
          if (resVal != null) {
            // Replace the resource offset with the real constant string
            varType = new VarType("Ljava/lang/String".getBytes());
            value = "\"" + resVal + "\"";
          }
        }
      }

      return;
    }
    else if (cl.getInstruction().getType() == InstructionType.CONST) {
      /*
       * Parse the type from the NEXT .local .line cl
       *
       * 41 const-string v7, "string"       <-- THE ORIGINAL CL
       * .line 43
       * .local v7, s:Ljava/lang/String;    <-- PARSE THIS LINE
       * .restart local v0 #name:type       <-- OR THIS LINE
       *
       * If no .local or .restart line is present, it is an anonymous constant
       */
      LinkedList<byte[]> splittedCl = Instruction.split(cl.getLine());
      byte[] constRegister = splittedCl.get(1);
      // Get the previous codeline
      CodeLine localCl = getNextMetadataLineForConstant(cl, MetaDataLine.LOCAL, constRegister);
      if (localCl != null) {
        constantType = ConstantType.LOCAL_VARIABLE; // parse it later
      } else if ((localCl = getNextMetadataLineForConstant(cl, MetaDataLine.RESTART_LOCAL, constRegister)) != null) {
        constantType = ConstantType.LOCAL_VARIABLE; // parse it later
      } else { // localCl = null, no corresponding line found
        constantType = ConstantType.LOCAL_ANONYMOUS_CONSTANT;
        /*
         * A little cheating here: If we have a const-string/jumbo or
         * const-string opcode, we know it is a string, but we do not
         * have the String class referenced as the type, so we just set
         * it here and we return a VarType of type String.
         */
        final byte[] constString = "const-string".getBytes(); // also covers const-string/jumbo
        final byte[] stringType = ("L" + STRING_DESCRIPTION).getBytes();
        if (cl.startsWith(constString)) { // it is a String
          varType = new VarType(stringType);
        } else { // it is not a String, make it UNKNOWN
          varType = new VarType(null);
          // manually set the constant description to, eg, const/4.
          varType.setTypeDescription(new String(splittedCl.getFirst()));
        }

        identifier = null; // it is an anonymous constant
        // nevertheless try to parse the value
        unparsedValue = new String(splittedCl.getLast());
        value = parseConstant(varType.getType(), unparsedValue);

        // Try to resolve a 32-bit resource offset into the associated string
        // http://stackoverflow.com/questions/6517151/how-does-the-mapping-between-android-resources-and-resources-id-work
        if (unparsedValue.startsWith("0x7f") && cl.startsWith("const ".getBytes())) {
          File bytecodeDir = cl.getSmaliClass().getApplication().getBytecodeDecompiledDirectory();
          String resourceName = ResourceUtils.findResourceNameForResourceId(bytecodeDir, unparsedValue);
          if (resourceName != null) {
            LOGGER.debug("Associated resource ID " + unparsedValue + " with resource name " + resourceName);
            String resVal = ResourceUtils.findStringValueForResourceName(bytecodeDir, resourceName);
            if (resVal != null) {
              // Replace the resource offset with the real constant string
              varType = new VarType("Ljava/lang/String".getBytes());
              value = "\"" + resVal + "\"";
            } else {
              // If the resource is no String (e.g. raw resource), exchange the ID with the resourceName
              varType = new VarType("Ljava/lang/String".getBytes());
              value = "\"" + resourceName + "\"";
            }
          }
        }

        return;
      }

      // At this point, we are trying to parse a LOCAL_VARIABLE
      /*
      Syntax:
      - Baksmali 1:
      .local v7, s:Ljava/lang/String;
      .local p1, cache:Lcom/memory/MemoryCacheAware;,"Lcom/memory/MemoryCacheAware<TK;TV;>;"
      .restart local v0 #name:type
      - Baksmali 2:
      .local v7, "s":Ljava/lang/String;
      .local p1, "memoryCache":Lcom/memory/MemoryCacheAware;, "Lcom/memory/MemoryCacheAware<Ljava/lang/String;Landroid/graphics/Bitmap;>;"
      .restart local v0 # "name":type
       */
      byte[] localLine = localCl.getLine();
      int colonIndex = ByteUtils.indexOf(localLine, ':');
      int commaIndex = ByteUtils.indexOf(localLine, ',');
      int hashIndex = ByteUtils.indexOf(localLine, '#');

      int identifierLeftIndex = 0;
      if (commaIndex > 0) // .local
        identifierLeftIndex = commaIndex + 1; // +2 would be ok too but +1 is more error-tolerant
      else if (hashIndex > 0) // .restart local
        identifierLeftIndex = hashIndex + 1;

      // remove the trailing ; from a non primitive type
      int offset = 0;
      if (localLine[localLine.length - 1] == ';')
        offset = 1;

      identifier = new String(ByteUtils.subbytes(localLine, identifierLeftIndex, colonIndex)).replace("\"", "").trim();
      varType = new VarType(ByteUtils.subbytes(localLine, colonIndex + 1, localLine.length - offset));
      unparsedValue = new String(splittedCl.getLast());
      value = parseConstant(varType.getType(), unparsedValue);
      return;
    }
    else if (cl.getInstruction().getType() == InstructionType.FILL_ARRAY_DATA) {
      constantType = ConstantType.ARRAY;

      /*
       * Code looks like this:
       *
       * fill-array-data v4, :array_0  <-- CURRENT INSTRUCTION
       * .line 55
       * .local v4, iiirrr:[I      <-- PARSE THIS LINE! (if statement)
       * new-array v4, v9, [I      <-- OR eventually this (else statement)
       *
       * First, find the line. Ignore empty lines etc. Use the register number to identify it correctly.
       */
      LinkedList<byte[]> split = Instruction.split(cl.getLine());
      byte[] arrayRegister = split.get(1);

      // Check for a .local line
      CodeLine localLine = getNextMetadataLineForConstant(cl, MetaDataLine.LOCAL, arrayRegister);
      if (localLine != null) {
        byte[] localLineCode = localLine.getLine();
        int colonIndex = ByteUtils.indexOf(localLineCode, ':');
        int commaIndex = ByteUtils.indexOf(localLineCode, ',');

        int identifierLeftIndex = 0;
        if (commaIndex > 0) // .local
          identifierLeftIndex = commaIndex + 1; // +2 would be ok too but +1 is more error-tolerant

        identifier = new String(ByteUtils.subbytes(localLineCode, identifierLeftIndex, colonIndex)).replace("\"", "").trim();
        varType = new VarType(ByteUtils.subbytes(localLineCode, colonIndex + 1, localLineCode.length));

        byte[] arrayLabel = cl.getInstruction().getLabel();
        value = parseFillArrayDataOpCode(arrayLabel, cl.getMethod());

        return;
      } else {
        LOGGER.trace("LocalLine was null, searching for previous new-array line");

        // Get the previous new-array line and parse the type from it
        int localLineNr = cl.getLineNr()-1; // current line index
        while (--localLineNr >= 0) {
          localLine = cl.getSmaliClass().getAllCodeLines().get(localLineNr);

          // skip all non-code lines
          if (!localLine.isCode()) continue;

          if (localLine.getInstruction().getType() == InstructionType.NEW_ARRAY &&
              Arrays.equals(localLine.getInstruction().getResultRegister(), arrayRegister)) {
            split = Instruction.split(localLine.getLine()); // do not use CL
            varType = new VarType(split.getLast());
            identifier = null;
            byte[] arrayLabel = cl.getInstruction().getLabel();
            value = parseFillArrayDataOpCode(arrayLabel, cl.getMethod());
            return;
          } else {
            // search missed :(
            break;
          }
        }

        // If we reach this we were unable to parse anything correctly
        throw new SyntaxException("Could not parse array constant!");
      }
    }
    else if (cl.getInstruction().getType() == InstructionType.INTERNAL_SMALI_OPCODE) {
      // This should only occur in rare situations. The opcode has no relevant infos for us, so just let everything unset.
      constantType = ConstantType.INTERNAL_BYTECODE_OP;
      varType = new VarType(null);
      identifier = null;
      value = null;
      return;
    }
    else if (cl.getInstruction().getType() == InstructionType.INVOKE ||
        cl.getInstruction().getType() == InstructionType.INVOKE_STATIC) {
      /*
       * invoke-virtual {v7}, Ljava/io/PrintStream;->println(Ljava/lang/String;)V
       *
       * We found an INVOKE and result was moved to the backtracked register. We therefore assume that the method returns
       * something of interest, eg, android.telephony.TelephonyManager.getDeviceId(). A constant will only be created if
       * the search is not fuzzy and only if the method is unknown, eg, an API method. Otherwise, the return values of the
       * method would normally be backtracked.
       */

      int cpIndex = ByteUtils.indexOf(cl.getLine(), ')');
      byte[] returnType = ByteUtils.subbytes(cl.getLine(), cpIndex+1);
      varType = new VarType(returnType);
      identifier = null;

      if (constType != null) { // triggered if constType i.e. ConstantType.NATIVE_METHOD
        constantType = constType;
        value = null;
      } else {
        constantType = ConstantType.EXTERNAL_METHOD;
        byte[][] cmp = cl.getInstruction().getCalledClassAndMethodWithParameter();
        value = new String(cmp[0]) + "->" + new String(cmp[1]) + "("+new String(cmp[2])+")"; // the class->method is our supposed value
      }

      return;
    }
    else if (cl.getInstruction().getType() == InstructionType.MATH_2C) {
      constantType = ConstantType.MATH_OPCODE_CONSTANT;
      LinkedList<byte[]> split = Instruction.split(cl.getLine());
      identifier = null;
      varType = new VarType(Type.MATH_OP, null);
      unparsedValue = new String(split.getLast());
      value = parseConstant(varType.getType(), unparsedValue);

      return;
    }
    else if (cl.getInstruction().getType() == InstructionType.NEW_ARRAY) {
      /*  It might be something like this:
       *  const/4 v0, 0x3                  <-- need to find, the dimension
       *  new-array v0, v0, [I              <-- found
       *  sput-object v0, Ltest/android/Testcase5;->a1:[I  <-- started
       *  Java code: private static final int[] a1 = { 0, 0, 0 };
       */
      LinkedList<byte[]> split = Instruction.split(cl.getLine());
      value = cl.toString(); // TODO: Parse the dimension (register needs to be tracked)!
      varType = new VarType(split.getLast());
      constantType = ConstantType.ARRAY;
      identifier = null;
      return;
    }

    // Something went wrong...
    throw new SyntaxException("Could not parse Constant, unknown type!");
  }

  /**
   * Convert a raw constant to a readable value based on it's type. If this method somehow fails, the original value is returned.
   * @param type the type of the constant
   * @param originalValue the original value
   * @return the converted value, eg, -1234 instead of -0x4d2 for integers
   */
  private static String parseConstant(Type type, String originalValue) {
    try {
      /*
       *  short, long and int need to have the 0x removed.
       *  short and long also need to have the trailing type removed.
       *  For example, an Integer looks like: .field public static final i:I = -0x4d2 which is -1234.
       */
      switch (type) {
        case SHORT:
          return "" + Short.parseShort(originalValue.substring(0, originalValue.length()-1).replaceFirst("0x", ""), 16);
        case INTEGER:
          return "" + Integer.parseInt(originalValue.replaceFirst("0x", ""), 16);
        case FLOAT:
          return "" + Float.parseFloat(originalValue);
        case DOUBLE:
          return "" + Double.parseDouble(originalValue);
        // case STRING:
        // TODO: Automatically decode UTF-8, UTF-16BE etc Strings like \u4e0d\u6b63\u306a\u6587\u5b57\u30b3\u30fc\u30c9
        // String x = StringEscapeUtils.unescapeJava(unicodestring); might do it
        //  return originalValue;
        case UNKNOWN: // same as default, mostly ints or longs
        case MATH_OP: // see above
        case LONG:
          /*
           * This is the LONG case, but also the default case for UNKNOWN types
           * eg: const-wide v2, 0x7b5bad595e238e38L
           * but const-wide v2, 0x7b5 is also possible
           * Negative: const/4 v7, -0x1
           */
          Matcher m = HEX_PATTERN.matcher(originalValue);
          if (m.matches()) { // we have something as above
            String hexValue = m.group(1);
            boolean isNegative = false;
            if (originalValue.startsWith("-")) {
              isNegative = true;
            }

            /*
             * Long.parseLong(hexValue, 16) fails if a double is passed in, e.g.:
             * const-wide/high16 v1, -0x8000000000000000L
             * --> hexValue = 8000000000000000
             * Possible fix: if opcode == const-wide/high16: use Double.parseDouble instead
             */
            return String.format("%s%d", isNegative?"-":"", Long.parseLong(hexValue, 16));
          }
          break;
          // else return original value (default case)
        default:
      }
    }
    catch (NumberFormatException e) {
      LOGGER.warn("Could not convert value '" + originalValue + "', type=" + type + ", e=" + e.getMessage());
    }

    return originalValue;
  }

  /**
   * Get the path in which the this constant was found.
   * @return the path, the last entry contains the found constant
   */
  public String getPath() {
    StringBuilder sb = new StringBuilder();
    for (BasicBlock bb : path) {
      sb.append(bb.getUniqueId());
      if (bb != path.getLast()) sb.append(" -> ");
    }

    return sb.toString();
  }

  /**
   * Search for the next .local or .local restart line from a given CodeLine to get more information about
   * a constant or an array. The search ends at the end of the Method the Codeline belongs to.
   *
   * @param currentLine the current codeline to begin the search after
   * @param mdl describes the line which is searched, this is either a .local or a ".restart local" line
   * @param register this is the register which must occur in the searched line
   * @return the found codeline or null if we find an opcode before any .local/.restart line
   * @throws SyntaxException if the next .local line has a register mismatch or the file ended
   */
  private static CodeLine getNextMetadataLineForConstant(CodeLine currentLine, MetaDataLine mdl, byte[] register) throws SyntaxException {
    int localLineNr = currentLine.getLineNr(); // this is already the next line index, line numbers start at 1
    Method method = currentLine.getMethod();

    int lastLineNrInMethod;
    if (method != null)
      lastLineNrInMethod = currentLine.getMethod().getCodeLines().getLast().getLineNr();
    else
      throw new SyntaxException("Cannot search for Metadata outside of a method.");

    while (localLineNr < lastLineNrInMethod) {
      CodeLine localLine = currentLine.getSmaliClass().getAllCodeLines().get(localLineNr);
      if (localLine.isCode()) {
        /*
         *  We found some other opcode and not a .local line. The constant we are searching information for
         *  is not assigned to any variable but the compiler just put some value into some register in order
         *  to use it for, eg, an array initialization as the array size parameter.
         *
         *  This will automatically stop at BB borders, as every jmp, goto etc instructions are considered to be code!
         */
        return null;
      }

      if (localLine.getInstruction().getType() == InstructionType.SMALI_DOT_COMMENT &&
          localLine.startsWith(mdl.lineStartsWith())) {

        LinkedList<byte[]> split = Instruction.split(localLine.getLine());
        /*
         * .local v0, name:type
         * .restart local v0, #name:type
         */
        int indexOfRegister;
        if (mdl == MetaDataLine.LOCAL)
          indexOfRegister = 1;
        else
          indexOfRegister = 2;
        byte[] localRegister = split.get(indexOfRegister);

        if (Arrays.equals(register, localRegister)) {
          return localLine;
        } else { // this should not happen, the next .local line should be the correct data for our array!
          // TODO: Is the above assumption always true? At least we should consider the BasicBlocks
          // and not stupidly iterate over all method codelines.
          LOGGER.debug("Found a .local line, but registers do not match! register=" + new String(register) + ", cl=" + localLine);
          //throw new SyntaxException("Found a .local line, but registers do not match! register="+new String(register)+", cl="+localLine);
        }
      }
      localLineNr++; // check the next line
    }

    LOGGER.debug("Unable to find a Metadata line, method ended!");

    return null;
  }

  /**
   * Parse something like this:
   *
   * fill-array-data v0, :array_0
   * ...
   * ...
   * :array_0 // the label!
   * .array-data 0x1
   *  0x78t
   *  0x79t
   *  0x7at
   * .end array-data
   *
   * The array is filled with this instruction. This should be the first instruction for this array after
   * it was created with a new-array opcode. Parse this instruction and end after it.
   *
   * 1) Get the label
   * 2) Search the label in the method, not the BB (should be at the end)
   * 3) Read the constants
   *
   * @param label the label
   * @param method the Method where the fill-array-data opcode was found
   * @return a string representation of the initial array content
   * @throws SyntaxException
   */
  private static String parseFillArrayDataOpCode(byte[] label, Method method) throws SyntaxException {
    LinkedList<CodeLine> methodCodeLines = method.getCodeLines();

    for (int mindex = 0; mindex < methodCodeLines.size(); mindex++) {
      CodeLine cl = methodCodeLines.get(mindex);

      if (cl.getInstruction().getType() == InstructionType.LABEL) {
        if (Arrays.equals(label, cl.getLine())) { // is it our label?
          mindex += 2; // skip the .array-data line, we are now at the first index (0x78t)
          cl = methodCodeLines.get(mindex);
          StringBuilder sb = new StringBuilder();
          sb.append("[ ");

          while (cl.getInstruction().getType() != InstructionType.SMALI_DOT_COMMENT) {
            sb.append(new String(cl.getLine()));
            sb.append(" ");
            cl = methodCodeLines.get(++mindex);
          }
          sb.append("]");

          return sb.toString();
        }
      }
    }

    throw new SyntaxException("Could not correctly parse the fill-array-data opcode. " +
        "No label '" + new String(label) + "' found!");
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj)
      return true;

    if (obj == null || getClass() != obj.getClass())
      return false;

    final Constant other = (Constant) obj;

    // A constant is considered equal to another constant, if they have the same CodeLine.
    return Objects.equals(this.getCodeLine(), other.getCodeLine());
  }

  @Override
  public int hashCode() {
    return cl.hashCode();
  }

  @Override
  public String toString() {
    String out = "CONST: constType=" + constantType;
    out += ", name=" + identifier;
    out += ", value=" + value;
    out += ", dataType=" + varType.getTypeDescription();
    out += ", arrayDim=" + varType.getArrayDimension();
    out += ", fuzzyLevel=" + fuzzyLevel;
    out += ", searchid=" + searchId;
    out += ", cl=" + cl;
    //out += "\npath=" + getPath();

    out += ", meth=" + cl.getSmaliClass().getFullClassName(false);

    return out;
  }

  public ConstantType getConstantType() {
    return constantType;
  }

  public String getVarTypeDescription() {
    return varType.getTypeDescription();
  }

  public String getIdentifier() {
    return identifier;
  }

  public int getFuzzyLevel() {
    return fuzzyLevel;
  }

  /**
   * @return Codeline Object where the constant came from
   */
  public CodeLine getCodeLine() {
    return cl;
  }

  /**
   * Return the parsed value. May be null if no value was assigned.
   * @return
   */
  public String getValue() {
    return value;
  }

  public String getUnparsedValue() {
    return unparsedValue;
  }
}
