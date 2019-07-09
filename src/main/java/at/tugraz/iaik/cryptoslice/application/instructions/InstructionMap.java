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

import com.google.common.collect.ImmutableMap;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.ByteBuffer;

// A small helper class which assigns a type to a SMALI opcode.
public class InstructionMap {
  private static final Logger LOGGER = LoggerFactory.getLogger(InstructionMap.class);
  private static final ImmutableMap<ByteBuffer, InstructionType> INSTRUCTIONS = ImmutableMap.<ByteBuffer, InstructionType> builder()
      .put(ByteBuffer.wrap("nop".getBytes()), InstructionType.NOP)

      .put(ByteBuffer.wrap("move".getBytes()), InstructionType.MOVE)
      .put(ByteBuffer.wrap("move/from16".getBytes()), InstructionType.MOVE)
      .put(ByteBuffer.wrap("move/16".getBytes()), InstructionType.MOVE)
      .put(ByteBuffer.wrap("move-wide".getBytes()), InstructionType.MOVE)
      .put(ByteBuffer.wrap("move-wide/from16".getBytes()), InstructionType.MOVE)
      .put(ByteBuffer.wrap("move-wide/16".getBytes()), InstructionType.MOVE)
      .put(ByteBuffer.wrap("move-object".getBytes()), InstructionType.MOVE)
      .put(ByteBuffer.wrap("move-object/from16".getBytes()), InstructionType.MOVE)
      .put(ByteBuffer.wrap("move-object/16".getBytes()), InstructionType.MOVE)

      .put(ByteBuffer.wrap("move-result".getBytes()), InstructionType.MOVE_RESULT)
      .put(ByteBuffer.wrap("move-result-wide".getBytes()), InstructionType.MOVE_RESULT)
      .put(ByteBuffer.wrap("move-result-object".getBytes()), InstructionType.MOVE_RESULT)

      .put(ByteBuffer.wrap("move-exception".getBytes()), InstructionType.INTERNAL_SMALI_OPCODE)

      .put(ByteBuffer.wrap("return-void".getBytes()), InstructionType.RETURN)
      .put(ByteBuffer.wrap("return".getBytes()), InstructionType.RETURN)
      .put(ByteBuffer.wrap("return-wide".getBytes()), InstructionType.RETURN)
      .put(ByteBuffer.wrap("return-object".getBytes()), InstructionType.RETURN)

      .put(ByteBuffer.wrap("const/4".getBytes()), InstructionType.CONST)
      .put(ByteBuffer.wrap("const/16".getBytes()), InstructionType.CONST)
      .put(ByteBuffer.wrap("const".getBytes()), InstructionType.CONST)
      .put(ByteBuffer.wrap("const/high16".getBytes()), InstructionType.CONST)
      .put(ByteBuffer.wrap("const-wide/16".getBytes()), InstructionType.CONST)
      .put(ByteBuffer.wrap("const-wide/32".getBytes()), InstructionType.CONST)
      .put(ByteBuffer.wrap("const-wide".getBytes()), InstructionType.CONST)
      .put(ByteBuffer.wrap("const-wide/high16".getBytes()), InstructionType.CONST)
      .put(ByteBuffer.wrap("const-string".getBytes()), InstructionType.CONST)
      .put(ByteBuffer.wrap("const-string/jumbo".getBytes()), InstructionType.CONST)
      .put(ByteBuffer.wrap("const-class".getBytes()), InstructionType.CONST)

      .put(ByteBuffer.wrap("monitor-enter".getBytes()), InstructionType.IGNORE)
      .put(ByteBuffer.wrap("monitor-exit".getBytes()), InstructionType.IGNORE)

      .put(ByteBuffer.wrap("check-cast".getBytes()), InstructionType.IGNORE)

      .put(ByteBuffer.wrap("instance-of".getBytes()), InstructionType.IGNORE)

      .put(ByteBuffer.wrap("array-length".getBytes()), InstructionType.INTERNAL_SMALI_OPCODE)

      .put(ByteBuffer.wrap("new-instance".getBytes()), InstructionType.NEW_INSTANCE)

      .put(ByteBuffer.wrap("new-array".getBytes()), InstructionType.NEW_ARRAY)

      .put(ByteBuffer.wrap("filled-new-array".getBytes()), InstructionType.FILLED_NEW_ARRAY)
      .put(ByteBuffer.wrap("filled-new-array/range".getBytes()), InstructionType.FILLED_NEW_ARRAY)
      .put(ByteBuffer.wrap("fill-array-data".getBytes()), InstructionType.FILL_ARRAY_DATA)

      .put(ByteBuffer.wrap("throw".getBytes()), InstructionType.IGNORE)

      .put(ByteBuffer.wrap("goto".getBytes()), InstructionType.GOTO)
      .put(ByteBuffer.wrap("goto/16".getBytes()), InstructionType.GOTO)
      .put(ByteBuffer.wrap("goto/32".getBytes()), InstructionType.GOTO)

      .put(ByteBuffer.wrap("packed-switch".getBytes()), InstructionType.SWITCH)
      .put(ByteBuffer.wrap("sparse-switch".getBytes()), InstructionType.SWITCH)

      .put(ByteBuffer.wrap("cmpkind".getBytes()), InstructionType.INTERNAL_SMALI_OPCODE)
      .put(ByteBuffer.wrap("cmpl-float".getBytes()), InstructionType.INTERNAL_SMALI_OPCODE)
      .put(ByteBuffer.wrap("cmpg-float".getBytes()), InstructionType.INTERNAL_SMALI_OPCODE)
      .put(ByteBuffer.wrap("cmpl-double".getBytes()), InstructionType.INTERNAL_SMALI_OPCODE)
      .put(ByteBuffer.wrap("cmpg-double".getBytes()), InstructionType.INTERNAL_SMALI_OPCODE)
      .put(ByteBuffer.wrap("cmp-long".getBytes()), InstructionType.INTERNAL_SMALI_OPCODE)

      .put(ByteBuffer.wrap("if-test".getBytes()), InstructionType.JMP)
      .put(ByteBuffer.wrap("if-eq".getBytes()), InstructionType.JMP)
      .put(ByteBuffer.wrap("if-ne".getBytes()), InstructionType.JMP)
      .put(ByteBuffer.wrap("if-lt".getBytes()), InstructionType.JMP)
      .put(ByteBuffer.wrap("if-ge".getBytes()), InstructionType.JMP)
      .put(ByteBuffer.wrap("if-gt".getBytes()), InstructionType.JMP)
      .put(ByteBuffer.wrap("if-le".getBytes()), InstructionType.JMP)
      .put(ByteBuffer.wrap("if-testz".getBytes()), InstructionType.JMP)
      .put(ByteBuffer.wrap("if-eqz".getBytes()), InstructionType.JMP)
      .put(ByteBuffer.wrap("if-nez".getBytes()), InstructionType.JMP)
      .put(ByteBuffer.wrap("if-ltz".getBytes()), InstructionType.JMP)
      .put(ByteBuffer.wrap("if-gez".getBytes()), InstructionType.JMP)
      .put(ByteBuffer.wrap("if-gtz".getBytes()), InstructionType.JMP)
      .put(ByteBuffer.wrap("if-lez".getBytes()), InstructionType.JMP)

      .put(ByteBuffer.wrap("aget".getBytes()), InstructionType.AGET)
      .put(ByteBuffer.wrap("aget-wide".getBytes()), InstructionType.AGET)
      .put(ByteBuffer.wrap("aget-object".getBytes()), InstructionType.AGET)
      .put(ByteBuffer.wrap("aget-boolean".getBytes()), InstructionType.AGET)
      .put(ByteBuffer.wrap("aget-byte".getBytes()), InstructionType.AGET)
      .put(ByteBuffer.wrap("aget-char".getBytes()), InstructionType.AGET)
      .put(ByteBuffer.wrap("aget-short".getBytes()), InstructionType.AGET)

      .put(ByteBuffer.wrap("aput".getBytes()), InstructionType.APUT)
      .put(ByteBuffer.wrap("aput-wide".getBytes()), InstructionType.APUT)
      .put(ByteBuffer.wrap("aput-object".getBytes()), InstructionType.APUT)
      .put(ByteBuffer.wrap("aput-boolean".getBytes()), InstructionType.APUT)
      .put(ByteBuffer.wrap("aput-byte".getBytes()), InstructionType.APUT)
      .put(ByteBuffer.wrap("aput-char".getBytes()), InstructionType.APUT)
      .put(ByteBuffer.wrap("aput-short".getBytes()), InstructionType.APUT)

      .put(ByteBuffer.wrap("iget".getBytes()), InstructionType.GET)
      .put(ByteBuffer.wrap("iget-wide".getBytes()), InstructionType.GET)
      .put(ByteBuffer.wrap("iget-object".getBytes()), InstructionType.GET)
      .put(ByteBuffer.wrap("iget-boolean".getBytes()), InstructionType.GET)
      .put(ByteBuffer.wrap("iget-byte".getBytes()), InstructionType.GET)
      .put(ByteBuffer.wrap("iget-char".getBytes()), InstructionType.GET)
      .put(ByteBuffer.wrap("iget-short".getBytes()), InstructionType.GET)

      .put(ByteBuffer.wrap("iput".getBytes()), InstructionType.PUT)
      .put(ByteBuffer.wrap("iput-wide".getBytes()), InstructionType.PUT)
      .put(ByteBuffer.wrap("iput-object".getBytes()), InstructionType.PUT)
      .put(ByteBuffer.wrap("iput-boolean".getBytes()), InstructionType.PUT)
      .put(ByteBuffer.wrap("iput-byte".getBytes()), InstructionType.PUT)
      .put(ByteBuffer.wrap("iput-char".getBytes()), InstructionType.PUT)
      .put(ByteBuffer.wrap("iput-short".getBytes()), InstructionType.PUT)

      .put(ByteBuffer.wrap("sget".getBytes()), InstructionType.GET)
      .put(ByteBuffer.wrap("sget-wide".getBytes()), InstructionType.GET)
      .put(ByteBuffer.wrap("sget-object".getBytes()), InstructionType.GET)
      .put(ByteBuffer.wrap("sget-boolean".getBytes()), InstructionType.GET)
      .put(ByteBuffer.wrap("sget-byte".getBytes()), InstructionType.GET)
      .put(ByteBuffer.wrap("sget-char".getBytes()), InstructionType.GET)
      .put(ByteBuffer.wrap("sget-short".getBytes()), InstructionType.GET)

      .put(ByteBuffer.wrap("sput".getBytes()), InstructionType.PUT)
      .put(ByteBuffer.wrap("sput-wide".getBytes()), InstructionType.PUT)
      .put(ByteBuffer.wrap("sput-object".getBytes()), InstructionType.PUT)
      .put(ByteBuffer.wrap("sput-boolean".getBytes()), InstructionType.PUT)
      .put(ByteBuffer.wrap("sput-byte".getBytes()), InstructionType.PUT)
      .put(ByteBuffer.wrap("sput-char".getBytes()), InstructionType.PUT)
      .put(ByteBuffer.wrap("sput-short".getBytes()), InstructionType.PUT)

      .put(ByteBuffer.wrap("invoke-virtual".getBytes()), InstructionType.INVOKE)
      .put(ByteBuffer.wrap("invoke-super".getBytes()), InstructionType.INVOKE)
      .put(ByteBuffer.wrap("invoke-direct".getBytes()), InstructionType.INVOKE)
      .put(ByteBuffer.wrap("invoke-interface".getBytes()), InstructionType.INVOKE)
      .put(ByteBuffer.wrap("invoke-virtual/range".getBytes()), InstructionType.INVOKE)
      .put(ByteBuffer.wrap("invoke-super/range".getBytes()), InstructionType.INVOKE)
      .put(ByteBuffer.wrap("invoke-direct/range".getBytes()), InstructionType.INVOKE)
      .put(ByteBuffer.wrap("invoke-interface/range".getBytes()), InstructionType.INVOKE)

      .put(ByteBuffer.wrap("invoke-static".getBytes()), InstructionType.INVOKE_STATIC)
      .put(ByteBuffer.wrap("invoke-static/range".getBytes()), InstructionType.INVOKE_STATIC)

      .put(ByteBuffer.wrap("neg-int".getBytes()), InstructionType.MATH_1)
      .put(ByteBuffer.wrap("not-int".getBytes()), InstructionType.MATH_1)
      .put(ByteBuffer.wrap("neg-long".getBytes()), InstructionType.MATH_1)
      .put(ByteBuffer.wrap("not-long".getBytes()), InstructionType.MATH_1)
      .put(ByteBuffer.wrap("neg-float".getBytes()), InstructionType.MATH_1)
      .put(ByteBuffer.wrap("neg-double".getBytes()), InstructionType.MATH_1)
      .put(ByteBuffer.wrap("int-to-long".getBytes()), InstructionType.MATH_1)
      .put(ByteBuffer.wrap("int-to-float".getBytes()), InstructionType.MATH_1)
      .put(ByteBuffer.wrap("int-to-double".getBytes()), InstructionType.MATH_1)
      .put(ByteBuffer.wrap("long-to-int".getBytes()), InstructionType.MATH_1)
      .put(ByteBuffer.wrap("long-to-float".getBytes()), InstructionType.MATH_1)
      .put(ByteBuffer.wrap("long-to-double".getBytes()), InstructionType.MATH_1)
      .put(ByteBuffer.wrap("float-to-int".getBytes()), InstructionType.MATH_1)
      .put(ByteBuffer.wrap("float-to-long".getBytes()), InstructionType.MATH_1)
      .put(ByteBuffer.wrap("float-to-double".getBytes()), InstructionType.MATH_1)
      .put(ByteBuffer.wrap("double-to-int".getBytes()), InstructionType.MATH_1)
      .put(ByteBuffer.wrap("double-to-long".getBytes()), InstructionType.MATH_1)
      .put(ByteBuffer.wrap("double-to-float".getBytes()), InstructionType.MATH_1)
      .put(ByteBuffer.wrap("int-to-byte".getBytes()), InstructionType.MATH_1)
      .put(ByteBuffer.wrap("int-to-char".getBytes()), InstructionType.MATH_1)
      .put(ByteBuffer.wrap("int-to-short".getBytes()), InstructionType.MATH_1)

      .put(ByteBuffer.wrap("add-int".getBytes()), InstructionType.MATH_2)
      .put(ByteBuffer.wrap("sub-int".getBytes()), InstructionType.MATH_2)
      .put(ByteBuffer.wrap("mul-int".getBytes()), InstructionType.MATH_2)
      .put(ByteBuffer.wrap("div-int".getBytes()), InstructionType.MATH_2)
      .put(ByteBuffer.wrap("rem-int".getBytes()), InstructionType.MATH_2)
      .put(ByteBuffer.wrap("and-int".getBytes()), InstructionType.MATH_2)
      .put(ByteBuffer.wrap("or-int".getBytes()), InstructionType.MATH_2)
      .put(ByteBuffer.wrap("xor-int".getBytes()), InstructionType.MATH_2)
      .put(ByteBuffer.wrap("shl-int".getBytes()), InstructionType.MATH_2)
      .put(ByteBuffer.wrap("shr-int".getBytes()), InstructionType.MATH_2)
      .put(ByteBuffer.wrap("ushr-int".getBytes()), InstructionType.MATH_2)
      .put(ByteBuffer.wrap("add-long".getBytes()), InstructionType.MATH_2)
      .put(ByteBuffer.wrap("sub-long".getBytes()), InstructionType.MATH_2)
      .put(ByteBuffer.wrap("mul-long".getBytes()), InstructionType.MATH_2)
      .put(ByteBuffer.wrap("div-long".getBytes()), InstructionType.MATH_2)
      .put(ByteBuffer.wrap("rem-long".getBytes()), InstructionType.MATH_2)
      .put(ByteBuffer.wrap("and-long".getBytes()), InstructionType.MATH_2)
      .put(ByteBuffer.wrap("or-long".getBytes()), InstructionType.MATH_2)
      .put(ByteBuffer.wrap("xor-long".getBytes()), InstructionType.MATH_2)
      .put(ByteBuffer.wrap("shl-long".getBytes()), InstructionType.MATH_2)
      .put(ByteBuffer.wrap("shr-long".getBytes()), InstructionType.MATH_2)
      .put(ByteBuffer.wrap("ushr-long".getBytes()), InstructionType.MATH_2)
      .put(ByteBuffer.wrap("add-float".getBytes()), InstructionType.MATH_2)
      .put(ByteBuffer.wrap("sub-float".getBytes()), InstructionType.MATH_2)
      .put(ByteBuffer.wrap("mul-float".getBytes()), InstructionType.MATH_2)
      .put(ByteBuffer.wrap("div-float".getBytes()), InstructionType.MATH_2)
      .put(ByteBuffer.wrap("rem-float".getBytes()), InstructionType.MATH_2)
      .put(ByteBuffer.wrap("add-double".getBytes()), InstructionType.MATH_2)
      .put(ByteBuffer.wrap("sub-double".getBytes()), InstructionType.MATH_2)
      .put(ByteBuffer.wrap("mul-double".getBytes()), InstructionType.MATH_2)
      .put(ByteBuffer.wrap("div-double".getBytes()), InstructionType.MATH_2)
      .put(ByteBuffer.wrap("rem-double".getBytes()), InstructionType.MATH_2)

      .put(ByteBuffer.wrap("add-int/2addr".getBytes()), InstructionType.MATH_1)
      .put(ByteBuffer.wrap("sub-int/2addr".getBytes()), InstructionType.MATH_1)
      .put(ByteBuffer.wrap("mul-int/2addr".getBytes()), InstructionType.MATH_1)
      .put(ByteBuffer.wrap("div-int/2addr".getBytes()), InstructionType.MATH_1)
      .put(ByteBuffer.wrap("rem-int/2addr".getBytes()), InstructionType.MATH_1)
      .put(ByteBuffer.wrap("and-int/2addr".getBytes()), InstructionType.MATH_1)
      .put(ByteBuffer.wrap("or-int/2addr".getBytes()), InstructionType.MATH_1)
      .put(ByteBuffer.wrap("xor-int/2addr".getBytes()), InstructionType.MATH_1)
      .put(ByteBuffer.wrap("shl-int/2addr".getBytes()), InstructionType.MATH_1)
      .put(ByteBuffer.wrap("shr-int/2addr".getBytes()), InstructionType.MATH_1)
      .put(ByteBuffer.wrap("ushr-int/2addr".getBytes()), InstructionType.MATH_1)
      .put(ByteBuffer.wrap("add-long/2addr".getBytes()), InstructionType.MATH_1)
      .put(ByteBuffer.wrap("sub-long/2addr".getBytes()), InstructionType.MATH_1)
      .put(ByteBuffer.wrap("mul-long/2addr".getBytes()), InstructionType.MATH_1)
      .put(ByteBuffer.wrap("div-long/2addr".getBytes()), InstructionType.MATH_1)
      .put(ByteBuffer.wrap("rem-long/2addr".getBytes()), InstructionType.MATH_1)
      .put(ByteBuffer.wrap("and-long/2addr".getBytes()), InstructionType.MATH_1)
      .put(ByteBuffer.wrap("or-long/2addr".getBytes()), InstructionType.MATH_1)
      .put(ByteBuffer.wrap("xor-long/2addr".getBytes()), InstructionType.MATH_1)
      .put(ByteBuffer.wrap("shl-long/2addr".getBytes()), InstructionType.MATH_1)
      .put(ByteBuffer.wrap("shr-long/2addr".getBytes()), InstructionType.MATH_1)
      .put(ByteBuffer.wrap("ushr-long/2addr".getBytes()), InstructionType.MATH_1)
      .put(ByteBuffer.wrap("add-float/2addr".getBytes()), InstructionType.MATH_1)
      .put(ByteBuffer.wrap("sub-float/2addr".getBytes()), InstructionType.MATH_1)
      .put(ByteBuffer.wrap("mul-float/2addr".getBytes()), InstructionType.MATH_1)
      .put(ByteBuffer.wrap("div-float/2addr".getBytes()), InstructionType.MATH_1)
      .put(ByteBuffer.wrap("rem-float/2addr".getBytes()), InstructionType.MATH_1)
      .put(ByteBuffer.wrap("add-double/2addr".getBytes()), InstructionType.MATH_1)
      .put(ByteBuffer.wrap("sub-double/2addr".getBytes()), InstructionType.MATH_1)
      .put(ByteBuffer.wrap("mul-double/2addr".getBytes()), InstructionType.MATH_1)
      .put(ByteBuffer.wrap("div-double/2addr".getBytes()), InstructionType.MATH_1)
      .put(ByteBuffer.wrap("rem-double/2addr".getBytes()), InstructionType.MATH_1)

      .put(ByteBuffer.wrap("add-int/lit16".getBytes()), InstructionType.MATH_2C)
      .put(ByteBuffer.wrap("rsub-int".getBytes()), InstructionType.MATH_2C)
      .put(ByteBuffer.wrap("mul-int/lit16".getBytes()), InstructionType.MATH_2C)
      .put(ByteBuffer.wrap("div-int/lit16".getBytes()), InstructionType.MATH_2C)
      .put(ByteBuffer.wrap("rem-int/lit16".getBytes()), InstructionType.MATH_2C)
      .put(ByteBuffer.wrap("and-int/lit16".getBytes()), InstructionType.MATH_2C)
      .put(ByteBuffer.wrap("or-int/lit16".getBytes()), InstructionType.MATH_2C)
      .put(ByteBuffer.wrap("xor-int/lit16".getBytes()), InstructionType.MATH_2C)

      .put(ByteBuffer.wrap("add-int/lit8".getBytes()), InstructionType.MATH_2C)
      .put(ByteBuffer.wrap("rsub-int/lit8".getBytes()), InstructionType.MATH_2C)
      .put(ByteBuffer.wrap("mul-int/lit8".getBytes()), InstructionType.MATH_2C)
      .put(ByteBuffer.wrap("div-int/lit8".getBytes()), InstructionType.MATH_2C)
      .put(ByteBuffer.wrap("rem-int/lit8".getBytes()), InstructionType.MATH_2C)
      .put(ByteBuffer.wrap("and-int/lit8".getBytes()), InstructionType.MATH_2C)
      .put(ByteBuffer.wrap("or-int/lit8".getBytes()), InstructionType.MATH_2C)
      .put(ByteBuffer.wrap("xor-int/lit8".getBytes()), InstructionType.MATH_2C)
      .put(ByteBuffer.wrap("shl-int/lit8".getBytes()), InstructionType.MATH_2C)
      .put(ByteBuffer.wrap("shr-int/lit8".getBytes()), InstructionType.MATH_2C)
      .put(ByteBuffer.wrap("ushr-int/lit8".getBytes()), InstructionType.MATH_2C)
      .build();

  public static InstructionType getType(byte[] opcode) {
    InstructionType t = INSTRUCTIONS.get(ByteBuffer.wrap(opcode));
    if (t == null) {
      LOGGER.debug("Found unkown opcode: " + new String(opcode) + " -- assigning UNKNOWN type.");
      return InstructionType.UNKNOWN;
    }

    return t;
  }
}
