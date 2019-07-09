package at.tugraz.iaik.cryptoslice.analysis;

import at.tugraz.iaik.cryptoslice.application.Application;
import at.tugraz.iaik.cryptoslice.application.CodeLine;
import at.tugraz.iaik.cryptoslice.application.SmaliClass;
import at.tugraz.iaik.cryptoslice.application.instructions.Instruction;
import at.tugraz.iaik.cryptoslice.application.instructions.InstructionType;
import at.tugraz.iaik.cryptoslice.utils.PermissionMapLoader;
import at.tugraz.iaik.cryptoslice.utils.config.ConfigHandler;
import at.tugraz.iaik.cryptoslice.utils.config.ConfigKeys;
import com.google.common.collect.Multimap;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

// Map permissions to API calls
public class PermissionCheckStep extends Step {
  private final Multimap<String, List<String>> permissionMap;
  private final List<CodeLine> invocationList = new ArrayList<>();
  private List<SmaliClass> smaliFiles;

  public PermissionCheckStep(boolean enabled) {
    this.name = "Permission Check";
    this.permissionMap = PermissionMapLoader.getInstance().getPermissionMap();
    this.enabled = enabled;
  }

  @Override
  public boolean doProcessing(Analysis analysis) throws AnalysisException {
    Application app = analysis.getApp();
    invocationList.clear();
    //this.heuristicResults = new ArrayList<>();
    this.smaliFiles = app.getAllSmaliClasses();

    if (permissionMap.isEmpty()) {
      LOGGER.warn("No API calls to search. Stopping analysis.");
      return false;
    }

    if (ConfigHandler.getInstance().getBooleanConfigValue(ConfigKeys.ANALYSIS_FILTER_ADNETWORKS) ||
        ConfigHandler.getInstance().getBooleanConfigValue(ConfigKeys.ANALYSIS_FILTER_CRYPTOLIBS)) {
      LOGGER.warn("Set " + ConfigKeys.ANALYSIS_FILTER_ADNETWORKS.toString() + " and " +
          ConfigKeys.ANALYSIS_FILTER_CRYPTOLIBS.toString() + " to false. Otherwise not all API calls might be found!");
    }

    LOGGER.debug("Analyzing " + app.getApplicationName() + " for " + permissionMap.size() + " API calls.");
    getInvocations();

    // TODO: Start based on permissions in the AndroidManifest file. Otherwise, we also find calls within libs even if
    // they are not actually used, e.g., Android Support
    for (Map.Entry<String, List<String>> apiCallAndPerm : permissionMap.entries()) {
      String apiCall = apiCallAndPerm.getKey();
      int parameterStart = apiCall.indexOf("(");
      String classAndMethod = (parameterStart == -1 ? apiCall : apiCall.substring(0, parameterStart)); // missing ( => no parameters
      int methodStart = classAndMethod.lastIndexOf("/");
      String className = classAndMethod.substring(0, methodStart);
      String methodName = classAndMethod.substring(methodStart + 1);

      for (CodeLine cl : invocationList) {
        Instruction i = cl.getInstruction();

        if (Arrays.equals(i.getCalledClassAndMethodWithParameter()[0], className.getBytes()) &&
            Arrays.equals(i.getCalledClassAndMethodWithParameter()[1], methodName.getBytes())) {

          List<String> permCombinations = apiCallAndPerm.getValue();
          if (!permCombinations.isEmpty())
            LOGGER.info("INVOKE in " + cl.getSmaliClass().getFullClassName(true) + " requires " + permCombinations.toString() + " on cl \n" + cl);

          //LOGGER.info("Found INVOKE pattern in " + cl.getSmaliClass().getFullClassName(true) + " on cl " + cl); // sf.getFile().getAbsolutePath()
          //heuristicResults.add(new HResult(pattern, cl));
        }
      }
    }



    /*for (Map.Entry<String, Set<HPattern>> patternGroup : heuristicPatterns.entrySet()) {
      switch (patternGroup.getKey()) {
        case "INVOKE":
          checkInvoke(patternGroup.getValue());
          break;
        case "SMALI":
          checkSmali(patternGroup.getValue());
          break;
        case "SUPERCLASS":
          checkSuperclass(patternGroup.getValue());
          break;
        case "PATCHED_CODE":
          checkPatchedCode(patternGroup.getValue());
          break;
        case "METHOD_DECLARATION":
          checkMethodDeclaration(patternGroup.getValue());
          break;
      }
    }

    LOGGER.info("Finished heuristic search for Application " + app.getApplicationName() +
        " with " + heuristicResults.size() + " results");
    analysis.setHeuristicResults(heuristicResults);*/

    return true;
  }

  private void getInvocations() {
    if (!invocationList.isEmpty()) {
      return;
    }

    for (SmaliClass sf : smaliFiles) {
      List<CodeLine> codeLines = sf.getAllCodeLines();

      for (CodeLine cl : codeLines) {
        Instruction i = cl.getInstruction();
        if (i.getType() == InstructionType.INVOKE || i.getType() == InstructionType.INVOKE_STATIC) {
          invocationList.add(cl);
          /*if (Arrays.equals(i.getCalledClassAndMethodWithParameter()[0], cm[0]) &&
              Arrays.equals(i.getCalledClassAndMethodWithParameter()[1], cm[1])) {
            LOGGER.info("Found INVOKE pattern in " + sf.getFullClassName(true) + " on cl " + cl); // sf.getFile().getAbsolutePath()
            heuristicResults.add(new HResult(pattern, cl));
          }*/
        }
      }
    }
  }
}
