package at.tugraz.iaik.cryptoslice.analysis.heuristic;

import at.tugraz.iaik.cryptoslice.analysis.Analysis;
import at.tugraz.iaik.cryptoslice.analysis.AnalysisException;
import at.tugraz.iaik.cryptoslice.analysis.Step;
import at.tugraz.iaik.cryptoslice.application.Application;
import at.tugraz.iaik.cryptoslice.application.CodeLine;
import at.tugraz.iaik.cryptoslice.application.SmaliClass;
import at.tugraz.iaik.cryptoslice.application.instructions.Instruction;
import at.tugraz.iaik.cryptoslice.application.instructions.InstructionType;
import at.tugraz.iaik.cryptoslice.application.methods.Method;
import at.tugraz.iaik.cryptoslice.utils.xml.XMLHPatternSource;

import java.util.*;

// Start a heuristic search for interesting patterns
public class HeuristicSearchStep extends Step {
  private final Map<String, Set<HPattern>> heuristicPatterns;
  private List<HResult> heuristicResults;
  private List<SmaliClass> smaliFiles;

  public HeuristicSearchStep(boolean enabled) {
    this.name = "Heuristic search";
    this.heuristicPatterns = XMLHPatternSource.getInstance().getPatterns();
    this.enabled = enabled;
  }

  @Override
  public boolean doProcessing(Analysis analysis) throws AnalysisException {
    Application app = analysis.getApp();
    this.heuristicResults = new ArrayList<>();
    this.smaliFiles = app.getAllSmaliClasses();

    if (heuristicPatterns.isEmpty()) {
      LOGGER.warn("No heuristic patterns to search. Stopping analysis.");
      return false;
    }

    LOGGER.debug("Analyzing " + app.getApplicationName() + " using " + heuristicPatterns.size() + " groups of heuristic patterns.");

    for (Map.Entry<String, Set<HPattern>> patternGroup : heuristicPatterns.entrySet()) {
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
        default:
      }
    }

    LOGGER.info("Finished heuristic search for Application " + app.getApplicationName() +
        " with " + heuristicResults.size() + " results");
    analysis.setHeuristicResults(heuristicResults);

    return true;
  }

  private void checkInvoke(Set<HPattern> patterns) {
    for (HPattern pattern : patterns) {
      if (pattern.isEnabled()) {
        //LOGGER.debug("\n\nSearching " + pattern.getPattern() + " (" + pattern.getType() + ")");

        String[] pat = pattern.getPattern().split("->");
        byte[][] cm = new byte[2][];
        cm[0] = pat[0].getBytes(); // Java package with class
        cm[1] = pat[1].getBytes(); // Java method

        for (SmaliClass sf : smaliFiles) {
          List<CodeLine> codeLines = sf.getAllCodeLines();

          for (CodeLine cl : codeLines) {
            Instruction i = cl.getInstruction();
            if (i.getType() == InstructionType.INVOKE || i.getType() == InstructionType.INVOKE_STATIC) {
              if (Arrays.equals(i.getCalledClassAndMethodWithParameter()[0], cm[0]) &&
                  Arrays.equals(i.getCalledClassAndMethodWithParameter()[1], cm[1])) {
                LOGGER.info("Found INVOKE pattern in " + sf.getFullClassName(true) + " on cl " + cl); // sf.getFile().getAbsolutePath()
                heuristicResults.add(new HResult(pattern, cl));
              }
            }
          }
        }
      }
    }
  }

  private void checkSmali(Set<HPattern> patterns) {
    for (SmaliClass sf : smaliFiles) {
      List<CodeLine> codeLines = sf.getAllCodeLines();

      for (CodeLine cl : codeLines) {
        for (HPattern pattern : patterns) {
          if (pattern.isEnabled()) {
            if (cl.contains(pattern.getPattern().getBytes())) {
              LOGGER.info("Found SMALI pattern in " + sf.getFullClassName(true) + " on cl " + cl); // sf.getFile().getAbsolutePath()
              heuristicResults.add(new HResult(pattern, cl));
            }
          }
        }
      }
    }
  }

  private void checkSuperclass(Set<HPattern> patterns) {
    for (HPattern pattern : patterns) {
      if (pattern.isEnabled()) {
        String superClass = pattern.getPattern();
        for (SmaliClass sf : smaliFiles) {
          if (superClass.equalsIgnoreCase(sf.getSuperClass().replace("/", "."))) {
            // Use the first codeline as it refers to the class which extends the superclass in question
            LOGGER.info("Found SUPERCLASS pattern in " + sf.getFullClassName(true) + ". Extending class: " + sf.getAllCodeLines().get(0));
            heuristicResults.add(new HResult(pattern, sf.getAllCodeLines().get(0)));
          }
        }
      }
    }
  }

  private void checkPatchedCode(Set<HPattern> patterns) {
    HPattern pattern = null;
    if (!patterns.isEmpty()) {
      pattern = patterns.iterator().next();
      if (!pattern.isEnabled())
        return;
    }

    for (SmaliClass sf : smaliFiles) {
      for (Method method : sf.getMethods()) {
        if (method.isProbablyPatched()) {
          LOGGER.info("Found PATCHED CODE pattern in " + sf.getFullClassName(true) + ". Method: " + method.getName());
          heuristicResults.add(new HResult(pattern, method));
        }
      }
    }
  }

  private void checkMethodDeclaration(Set<HPattern> patterns) {
    for (SmaliClass sf : smaliFiles) {
      for (HPattern pattern : patterns) {
        if (pattern.isEnabled()) {
          for (Method method : sf.getMethods()) {
            if (method.getCodeLines().getFirst().contains(pattern.getPattern().getBytes())) {
              LOGGER.info("Found METHOD DECLARATION pattern in " + sf.getFullClassName(true) +
                  ": " + method.getCodeLines().getFirst());
              heuristicResults.add(new HResult(pattern, method.getCodeLines().getFirst()));
            }
          }
        }
      }
    }
  }
}
