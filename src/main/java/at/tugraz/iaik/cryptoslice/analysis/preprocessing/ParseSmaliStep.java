package at.tugraz.iaik.cryptoslice.analysis.preprocessing;

import at.tugraz.iaik.cryptoslice.analysis.Analysis;
import at.tugraz.iaik.cryptoslice.analysis.AnalysisException;
import at.tugraz.iaik.cryptoslice.analysis.Step;
import at.tugraz.iaik.cryptoslice.application.Application;
import at.tugraz.iaik.cryptoslice.application.SmaliClass;

import java.io.File;
import java.util.List;

// Parses .smali files into an object-model
public class ParseSmaliStep extends Step {
  public ParseSmaliStep(boolean enabled) {
    this.name = "Parse Smali";
    this.enabled = enabled;
  }

  @Override
  public boolean doProcessing(Analysis analysis) throws AnalysisException {
    Application app = analysis.getApp();

    /*
    HashMap<String, SmaliClass> smaliClassMap = new HashMap<>();
    int smaliClassLabel = app.getSmaliClassLabel();
    for (File smaliFile : app.getAllRawSmaliFiles()) {
      SmaliClass sc;
      try {
        sc = new SmaliClass(smaliFile, app, smaliClassLabel++);
        smaliClassMap.put(smaliFile.getAbsolutePath(), sc);
      } catch (IOException | DetectionLogicError | SmaliClassError e) {
        throw new AnalysisException(e);
      }
    }

    app.setAllSmaliClasses(smaliClassMap);
    app.setSmaliClassLabel(smaliClassLabel);*/

    List<File> rawSmaliFiles = app.getAllRawSmaliFiles();
    List<SmaliClass> smaliClassList = app.getAllSmaliClasses();
    if (smaliClassList.size() != rawSmaliFiles.size()) {
      throw new AnalysisException("Parsing error!");
    }

    return true;
  }
}
