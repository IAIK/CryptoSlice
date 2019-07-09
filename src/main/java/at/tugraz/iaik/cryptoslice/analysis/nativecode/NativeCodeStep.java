package at.tugraz.iaik.cryptoslice.analysis.nativecode;

import at.tugraz.iaik.cryptoslice.analysis.Analysis;
import at.tugraz.iaik.cryptoslice.analysis.AnalysisException;
import at.tugraz.iaik.cryptoslice.analysis.Step;
import at.tugraz.iaik.cryptoslice.analysis.slicing.SliceNode;
import at.tugraz.iaik.cryptoslice.analysis.slicing.SlicerBackward;
import at.tugraz.iaik.cryptoslice.analysis.slicing.SlicingCriterion;
import at.tugraz.iaik.cryptoslice.analysis.slicing.SlicingPatternBT;
import at.tugraz.iaik.cryptoslice.analysis.slicinganalysis.CryptoRule;
import at.tugraz.iaik.cryptoslice.application.CodeLine;
import at.tugraz.iaik.cryptoslice.application.DetectionLogicError;
import at.tugraz.iaik.cryptoslice.application.SmaliClass;
import at.tugraz.iaik.cryptoslice.application.instructions.Constant;
import at.tugraz.iaik.cryptoslice.application.methods.Method;
import at.tugraz.iaik.cryptoslice.utils.FileList;
import at.tugraz.iaik.cryptoslice.utils.PathFinder;

import java.io.File;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;

// Searches for native code relations
public class NativeCodeStep extends Step {
  private Analysis analysis;
  private final List<CodeLine> searchIds = new ArrayList<>();

  public NativeCodeStep(boolean enabled) {
    this.name = "NativeCode";
    this.enabled = enabled;
  }

  @Override
  public boolean doProcessing(Analysis analysis) throws AnalysisException {
    this.analysis = analysis;

    findNativeMethods();
    findNativeLibs();
    findNativeLibsLoading();

    /*try {
      File f = new File("libGProtector_armeabi.so");
      ReadElf re = ReadElf.read(f);
      System.out.println("is dyn: " + re.isDynamic());
      System.out.println("is pie: " + re.isPIE());
      System.out.println("class: " + re.getElfClass());
      System.out.println("type: " + re.getType());
      System.out.println("machine: " + re.getMachine());

      Map<String, ReadElf.Symbol> symbolMap = re.getSymbols();
      if (symbolMap != null) {
        for (Map.Entry<String, ReadElf.Symbol> entry : symbolMap.entrySet()) {
          ReadElf.Symbol symbol = entry.getValue();

          System.out.println("sym entry: " + entry.getKey() + " | value: 0x" + symbol.getValueHex() +
              ", binding: " + symbol.getBinding() + ", type: " + symbol.getType());
        }
      }

      Map<String, ReadElf.Symbol> dynamicSymbolMap = re.getDynamicSymbols();
      if (dynamicSymbolMap != null) {
        for (Map.Entry<String, ReadElf.Symbol> entry : dynamicSymbolMap.entrySet()) {
          ReadElf.Symbol symbol = entry.getValue();

          System.out.println("dyn entry: " + entry.getKey() + " | value: 0x" + symbol.getValueHex() +
              ", binding: " + symbol.getBinding() + ", type: " + symbol.getType());
        }
      }
    } catch (Exception e) {
      e.printStackTrace();
    }*/

    return true;
  }

  private void findNativeMethods() {
    // Determine all native methods
    List<Method> nativeMethods = new ArrayList<>();
    List<SmaliClass> smaliClasses = analysis.getApp().getAllSmaliClasses();
    for (SmaliClass smaliClass : smaliClasses) {
      List<Method> methods = smaliClass.getMethods();
      for (Method method : methods) {
        if (method.isNative()) {
          nativeMethods.add(method);
        }
      }
    }

    if (nativeMethods.isEmpty()) {
      LOGGER.error("No native methods found!");
      return;
    }

    for (Method nativeMethod : nativeMethods) {
      //System.out.println(nativeMethod);
    }

    // hashset bringt nix zum uniquen weil equals auf smaliClass filtert
  }

  private List<File> findNativeLibs() {
    FileList fileList = new FileList(analysis.getApp().getBytecodeDecompiledDirectory(), ".so");
    List<File> allfoundFiles = fileList.getAllFoundFiles();
    for (File a : allfoundFiles) {
      LOGGER.info("Native Library: " + a);
    }

    return fileList.getAllFoundFiles();
  }

  private List<String> findNativeLibsLoading() throws AnalysisException {
    List<String> libraryPaths = new ArrayList<>();

    try {
      SlicingPatternBT pattern1 = new SlicingPatternBT("java/lang/System", "loadLibrary", "Ljava/lang/String;", 0, "");
      SlicingPatternBT pattern2 = new SlicingPatternBT("java/lang/System", "load", "Ljava/lang/String;", 0, "");
      SlicingCriterion criterion = new SlicingCriterion(pattern1);
      SlicerBackward slicer = new SlicerBackward(analysis.getApp(), searchIds);
      slicer.startSearch(criterion);
      criterion.setPattern(pattern2);
      slicer.startSearch(criterion);

      if (criterion.getSliceConstants().isEmpty()) {
        LOGGER.info("findLibs: No native library loading found or no library names found!");
        return libraryPaths;
      }

      for (Integer searchId : criterion.getSliceTrees().keySet()) {
        CodeLine startLine = searchIds.get(searchId);
        LOGGER.info("\nFound library loading in method " +
            startLine.getMethod().getReadableJavaName() + " in line " + startLine.getLineNr());

        List<SliceNode> libs = CryptoRule.rankNodes(PathFinder.getLeafs(criterion.getSliceTrees().get(searchId)),
            EnumSet.of(CryptoRule.FILTER.ALLOW_STRING));

        if (!libs.isEmpty()) {
          for (SliceNode lib : libs) {
            Constant libNode = lib.getConstant();
            String libValue = CryptoRule.stripEnclosingQuotes(libNode.getValue());
            LOGGER.info("Library: " + libValue);

            // TODO: Matching with known libs (@findNativeLibs)
          }
        } else {
          LOGGER.warn("Unable to determine the library name!");
        }
      }

    } catch (DetectionLogicError e) {
      throw new AnalysisException(e);
    }

    return libraryPaths;
  }
}
