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

import at.tugraz.iaik.cryptoslice.application.instructions.Instruction;
import at.tugraz.iaik.cryptoslice.application.methods.Method;
import at.tugraz.iaik.cryptoslice.utils.ByteUtils;
import at.tugraz.iaik.cryptoslice.utils.FileList;
import com.google.common.collect.ImmutableList;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.*;

public class SmaliClass {
  private static final Logger LOGGER = LoggerFactory.getLogger(SmaliClass.class);

  private final File smaliFile;
  private final Application app;
  private final int label;
  private final JavaPackage javaPackage;

  private static final byte[] START_METHOD = ".method ".getBytes();
  private static final byte[] END_METHOD = ".end method".getBytes();
  private static final byte[] IMPLEMENTS = ".implements ".getBytes();
  private static final byte[] SUPER = ".super ".getBytes();
  private static final byte[] CLASS = ".class ".getBytes();
  private static final byte[] SOURCE = ".source ".getBytes();

  private ImmutableList<CodeLine> codeLineList;
  private ImmutableList<Method> methodList;
  private ImmutableList<Field> fieldList;
  private final Set<String> implementedInterfaces = new HashSet<String>();
  private String superClass = null;
  private String sourceFile = null;
  private boolean isAbstract = false;

  public SmaliClass(File smaliFile, Application app, int label) throws IOException, DetectionLogicError, SmaliClassError {
    this.smaliFile = smaliFile;
    this.app = app;
    this.label = label;
    this.javaPackage = new JavaPackage(app);

    LOGGER.debug("Parsing SMALI code for file {}", smaliFile.getName());
    parse();
  }

  /**
   * Parse the codelines.
   * @throws IOException
   * @throws DetectionLogicError if the BBs could not be correctly labeled
   * @throws SmaliClassError
   */
  private void parse() throws IOException, DetectionLogicError, SmaliClassError {
    List<CodeLine> codeLines = new ArrayList<>();
    try (FileInputStream fis = new FileInputStream(smaliFile);
         BufferedInputStream bis = new BufferedInputStream(fis)) {
      int lineNr = 1;
      byte[] line;

      while ((line = ByteUtils.parseLine(bis)) != null) {
        codeLines.add(new CodeLine(line, lineNr++, this));
      }
    }

    /*LineIterator it = FileUtils.lineIterator(smaliFile, "UTF-8");
    int lineNr = 1;
    try {
      while (it.hasNext())
        codeLineList.add(new CodeLine(it.nextLine().getBytes(), lineNr++, this));
    } finally {
      LineIterator.closeQuietly(it);
    }*/

    codeLineList = ImmutableList.copyOf(codeLines);

    LinkedList<CodeLine> blockedCodeLines = new LinkedList<CodeLine>();
    // All codelines not belonging to a method. Fields, enums, Annotations etc.
    LinkedList<CodeLine> otherCL = new LinkedList<CodeLine>();

    /*
     * TODO:
     * :array_0
     * .array-data 0x1
     *  0x78t <- is wrongly parsed b/c it is assumed to be an instruction, should also not be put into the BB
     *  0x79t <- see above
     *  0x7at <- see above
     * .end array-data
     */
    boolean insideMethod = false;
    int methodLabel = 0;
    List<Method> methods = new ArrayList<>();
    for (CodeLine cl : codeLineList) {
      if (cl.isEmpty()) continue; // skip empty lines
      if (insideMethod) {
        if (ByteUtils.startsWith(cl.getLine(), END_METHOD)) {
          // append, store method
          blockedCodeLines.addLast(cl);

          Method m = new Method(blockedCodeLines, this, methodLabel++); // save
          LOGGER.debug("Parsing instructions/opcodes for method '{}'", m.getName());
          for (CodeLine bcl : blockedCodeLines) {
            bcl.setMethod(m); // set a reference to the method for later and faster access
            bcl.getInstruction().parseOpCode();
          }
          m.generateBBs();

					/* This is a "fix" for empty methods. Otherwise, this would happen:
					 * Method.getFirstBasicBlock with this content
					 *   .method public abstract PpNzwq9T()Ljava/util/List;
					 *   .end method
					 * produces a java.util.NoSuchElementException.
					 */
          if (!m.getBasicBlocks().isEmpty()) methods.add(m);

          blockedCodeLines = new LinkedList<CodeLine>(); // reset
          insideMethod = false;
        } else { // do not append .line to the method
          if (!ByteUtils.startsWith(cl.getLine(), ".line".getBytes()))
            blockedCodeLines.addLast(cl);
        }
      } else {
        if (ByteUtils.startsWith(cl.getLine(), START_METHOD)) {
          // new block and append
          blockedCodeLines.addLast(cl); // either still empty or reseted in END
          insideMethod = true;
        } else {
          // append to otherCL
          otherCL.addLast(cl);
        }
      }
    }

    methodList = ImmutableList.copyOf(methods);
    fieldList = ImmutableList.copyOf(Field.parseAllFields(otherCL));

    // Parse implements, class and super lines
    for (CodeLine cl : otherCL) {
      if (cl.startsWith(SUPER)) { // .super Landroid/app/Activity;
        byte[] tmp = Instruction.split(cl.getLine()).getLast();
        superClass = new String(ByteUtils.subbytes(tmp, 1, tmp.length-1));
      }
      else if (cl.startsWith(IMPLEMENTS)) { // .implements Ljava/io/Serializable;
        byte[] tmp = Instruction.split(cl.getLine()).getLast();
        implementedInterfaces.add(new String(ByteUtils.subbytes(tmp, 1, tmp.length-1)));
      }
      else if (cl.startsWith(CLASS)) { // .class public Ltest/android/AndroidTestActivity;
        isAbstract = cl.contains(" abstract ".getBytes());

        byte[] tmp = Instruction.split(cl.getLine()).getLast();
        List<String> packageNames = new ArrayList<String>();
        String x[] = new String(ByteUtils.subbytes(tmp, 1, tmp.length-1)).split("/");
        for (int i = 0; i < x.length-1; i++) // do not include the class name
          packageNames.add(x[i]);
        this.javaPackage.setName(packageNames);
      }
      else if (cl.startsWith(SOURCE)) { // .source "MagicSMSActivity.java"
        byte[] tmp = Instruction.split(cl.getLine()).getLast();
        sourceFile = new String(ByteUtils.subbytes(tmp, 1, tmp.length-1));
      }
    }
  }

  public String getPackageName(boolean useDots) {
    return this.javaPackage.getName(useDots);
  }

  public String getFullClassName(boolean useDots) {
    String separator = "/";
    if (useDots)
      separator = ".";

    if (getPackageName(useDots).isEmpty())
      return getClassName();

    return getPackageName(useDots) + separator + getClassName();
  }

  public Method getMethodByName(String methodName) {
    for (Method method : methodList) {
      if (method.getName().equals(methodName)) {
        return method;
      }
    }

    return null;
  }

  public boolean extendsClass(String fullClassName) {
    return (superClass != null && superClass.equals(fullClassName));
  }

  public boolean implementsInterface(String interfaceName) {
    return implementedInterfaces.contains(interfaceName);
  }

  public Application getApplication() {
    return app;
  }

  public String getClassName() {
    return smaliFile.getName().replace(FileList.SMALI_FILES, "");
  }

  public File getFile() {
    return smaliFile;
  }

  public String getSuperClass() {
    return superClass;
  }

  public Set<String> getImplementedInterfaces() {
    return implementedInterfaces;
  }

  public String getUniqueId() {
    return String.valueOf(label);
  }

  public List<CodeLine> getAllCodeLines() {
    return codeLineList;
  }

  public List<Method> getMethods() {
    return methodList;
  }

  public List<Field> getAllFields() {
    return fieldList;
  }

  public boolean isAbstract() {
    return isAbstract;
  }

  @Override
  public int hashCode() {
    return Objects.hash(smaliFile, label, javaPackage, superClass, sourceFile);
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj)
      return true;

    if (obj == null || getClass() != obj.getClass())
      return false;

    final SmaliClass other = (SmaliClass) obj;

    return Objects.equals(this.smaliFile, other.smaliFile)
        && Objects.equals(this.label, other.label)
        && Objects.equals(this.javaPackage, other.javaPackage)
        && Objects.equals(this.superClass, other.superClass)
        && Objects.equals(this.sourceFile, other.sourceFile);
  }

  @Override
  public String toString() {
    return getClassName();
  }
}
