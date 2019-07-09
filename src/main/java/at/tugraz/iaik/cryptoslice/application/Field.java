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
package at.tugraz.iaik.cryptoslice.application;

import at.tugraz.iaik.cryptoslice.utils.ByteUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.EnumSet;
import java.util.LinkedList;

public class Field {
  /**
   * All possible modifiers.
   */
  public enum Modifier {
    PUBLIC("public".getBytes()),
    PROTECTED("protected".getBytes()),
    PRIVATE("private".getBytes()),
    STATIC("static".getBytes()),
    ABSTRACT("abstract".getBytes()),
    SYNCHRONIZED("synchronized".getBytes()),
    TRANSIENT("transient".getBytes()),
    VOLATILE("volatile".getBytes()),
    FINAL("final".getBytes()),
    NATIVE("native".getBytes());

    private byte[] text;

    private Modifier(byte[] text) {
      this.text = text;
    }

    public byte[] getBytePresentation() {
      return text;
    }

    @Override
    public String toString() {
      return new String(text);
    }
  }

  private static final Logger LOGGER = LoggerFactory.getLogger(Field.class);

  private final CodeLine cl;
  private final EnumSet<Modifier> modifierSet = EnumSet.noneOf(Modifier.class);
  public static final byte[] FIELD = ".field ".getBytes();
  private String fieldName = null;

  public Field(CodeLine cl) throws SyntaxException {
    // parse the line and add it to the set
    for (Modifier modifier : Modifier.values()) {
      if (cl.contains(modifier.getBytePresentation())) {
        // FIXME: public int privateBlah = 0; would yield public and private!
        modifierSet.add(modifier);
      }
    }

    this.cl = cl;
  }

  /**
   * Parse all Fields from the given CodeLines.
   *
   * @param codeLines
   * @return
   */
  public static LinkedList<Field> parseAllFields(LinkedList<CodeLine> codeLines) {
    LinkedList<Field> fieldList = new LinkedList<Field>();

    for (CodeLine codeLine : codeLines) {
      if (codeLine.startsWith(FIELD)) {
        try {
          Field f = new Field(codeLine);
          fieldList.add(f);
        } catch (SyntaxException e) {
          LOGGER.error("Could not parse field ",e);
        }
      }
    }

    return fieldList;
  }

  public String getFieldName() {
    if (fieldName == null) {
      int colonIndex = ByteUtils.indexOf(cl.getLine(), ':');
      int spaceBeforeColonPos = ByteUtils.indexOfReverse(cl.getLine(), ' ', colonIndex);
      fieldName = new String(ByteUtils.subbytes(cl.getLine(), spaceBeforeColonPos+1, colonIndex));
    }

    return fieldName;
  }

  /**
   * Print the field and its description.
   */
  @Override
  public String toString() {
    return cl.toString();
  }

  public CodeLine getCodeLine() {
    return cl;
  }

  public boolean hasModifier(Modifier modifier) {
    return modifierSet.contains(modifier);
  }

  public boolean isStatic() {
    return hasModifier(Modifier.STATIC);
  }

  public boolean isFinal() {
    return hasModifier(Modifier.FINAL);
  }
}
