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

import at.tugraz.iaik.cryptoslice.application.methods.Method;
import at.tugraz.iaik.cryptoslice.utils.FileList;
import com.google.common.collect.ImmutableList;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.util.*;

public class Application {
  private static final Logger LOGGER = LoggerFactory.getLogger(Application.class);

  private final File apkFile;
  private final String applicationName;

  private File bytecodeDirectory = null;
  private File appWorkingDirectory = null;
  private File bytecodeApkDirectory = null;
  private File bytecodeDecompiledDirectory = null;
  private File smaliDirectory = null;

  private FileList allSmaliClasses = null;
  private int smaliClassLabel = 0;
  private final Map<String, SmaliClass> smaliClassMap = new HashMap<>();
  private boolean parsedAllSmaliClasses = false;

  public Application(File apk) {
    this.apkFile = apk;
    this.applicationName = apk.getName().substring(0, apk.getName().length() - 4);
  }

  public SmaliClass getSmaliClass(File file) {
    SmaliClass sf = smaliClassMap.get(file.getAbsolutePath());
    if (sf == null) {
      try {
        if (!file.exists()) {
          return null;
        }

        sf = new SmaliClass(file, this, smaliClassLabel++);
        smaliClassMap.put(file.getAbsolutePath(), sf);
      } catch (IOException | DetectionLogicError | SmaliClassError e) {
        LOGGER.error("Could not create SmaliClass object", e);
      }
    }

    return sf;
  }

  public List<SmaliClass> getAllSmaliClasses() {
    if (!parsedAllSmaliClasses) {
      for (File rawFile : getAllRawSmaliFiles()) {
        getSmaliClass(rawFile);
      }
      parsedAllSmaliClasses = true;
    }

    return ImmutableList.copyOf(smaliClassMap.values());
  }

  public List<File> getAllRawSmaliFiles() {
    if (allSmaliClasses == null)
      allSmaliClasses = new FileList(smaliDirectory, FileList.SMALI_FILES);

    return allSmaliClasses.getAllFoundFiles();
  }

  public Method getMethodByClassAndName(String className, String methodName,
                                        byte[] methodParameters, byte[] returnValue)
      throws ClassOrMethodNotFoundException {

    String methodParametersStr = (methodParameters != null) ? new String(methodParameters) : "";
    String returnValueStr = (returnValue != null) ? new String(returnValue) : "";

    // Quickly exclude classes which we certainly will not find
    if (!className.startsWith("java/io/") && !className.startsWith("java/lang/") &&
        !className.startsWith("java/util/") && !className.startsWith("android/app/") && !className.startsWith("android/widget/")) {

      File f = new File(smaliDirectory, className + FileList.SMALI_FILES);
      SmaliClass sf = getSmaliClass(f);

      if (sf != null) {
        for (Method method : sf.getMethods()) {
          // methodParameters could be null but method.getParameters is never, since ByteUtils.subBytes returns at least byte[0] empty
          //if (method.getName().equals(methodName) && Arrays.equals(parameterDeclaration, method.getParameters()) && Arrays.equals(returnValue, method.getReturnValue())) {
          if (method.getName().equals(methodName) && method.getParameterString().equals(methodParametersStr) &&
              new String(method.getReturnValue()).equals(returnValueStr)) {
            return method;
          }
        }

        // If none is found, also check occasional super classes recursively
        if (sf.getSuperClass() != null) {
          try {
            return getMethodByClassAndName(sf.getSuperClass(), methodName, methodParameters, returnValue);
          } catch (ClassOrMethodNotFoundException e) {
          }
        }
      }
    }

    String s = "Lost track, class unknown: " + className + "->" + methodName + "(" + methodParametersStr + ")";
    throw new ClassOrMethodNotFoundException(s);
  }

  public SmaliClass getSmaliClassByClassName(String className) {
    return getSmaliClass(new File(smaliDirectory, className + FileList.SMALI_FILES));
  }

  @Override
  public String toString() {
    return "Application [applicationName=" + applicationName + "]";
  }

  public File getApkFile() {
    return apkFile;
  }

  public String getApplicationName() {
    return applicationName;
  }

  public File getBytecodeDirectory() {
    return bytecodeDirectory;
  }

  public void setBytecodeDirectory(File bytecodeDirectory) {
    this.bytecodeDirectory = bytecodeDirectory;
  }

  public File getAppWorkingDirectory() {
    return appWorkingDirectory;
  }

  public void setAppWorkingDirectory(File appWorkingDirectory) {
    this.appWorkingDirectory = appWorkingDirectory;
  }

  public File getBytecodeApkDirectory() {
    return bytecodeApkDirectory;
  }

  public void setBytecodeApkDirectory(File bytecodeApkDirectory) {
    this.bytecodeApkDirectory = bytecodeApkDirectory;
  }

  public File getBytecodeDecompiledDirectory() {
    return bytecodeDecompiledDirectory;
  }

  public void setBytecodeDecompiledDirectory(File bytecodeDecompiledDirectory) {
    this.bytecodeDecompiledDirectory = bytecodeDecompiledDirectory;
  }

  public File getSmaliDirectory() {
    return smaliDirectory;
  }

  public void setSmaliDirectory(File smaliDirectory) {
    this.smaliDirectory = smaliDirectory;
  }

  public int getSmaliClassLabel() {
    return smaliClassLabel;
  }

  public void setSmaliClassLabel(int smaliClassLabel) {
    this.smaliClassLabel = smaliClassLabel;
  }
}
