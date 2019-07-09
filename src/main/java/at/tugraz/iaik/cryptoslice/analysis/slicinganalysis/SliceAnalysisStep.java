package at.tugraz.iaik.cryptoslice.analysis.slicinganalysis;

import at.tugraz.iaik.cryptoslice.analysis.Analysis;
import at.tugraz.iaik.cryptoslice.analysis.AnalysisException;
import at.tugraz.iaik.cryptoslice.analysis.Step;
import at.tugraz.iaik.cryptoslice.application.DetectionLogicError;
import org.stringtemplate.v4.ST;

// Investigates the slice tree for interesting patterns
public class SliceAnalysisStep extends Step {

  public SliceAnalysisStep(boolean enabled) {
    this.name = "Analysis of slicing results";
    this.enabled = enabled;
  }

  @Override
  public boolean doProcessing(Analysis analysis) throws AnalysisException {
    ST sliceAnalysisReport = analysis.getReport().getTemplate("sliceAnalysis");

    try {
      sliceAnalysisReport.add("cryptoRules", new Rule1(analysis).check());
      sliceAnalysisReport.add("cryptoRules", new Rule2(analysis).check());
      sliceAnalysisReport.add("cryptoRules", new Rule3(analysis).check());
      sliceAnalysisReport.add("cryptoRules", new Rule4(analysis).check());
      sliceAnalysisReport.add("cryptoRules", new Rule5(analysis).check());
      sliceAnalysisReport.add("cryptoRules", new Rule6(analysis).check());
      sliceAnalysisReport.add("cryptoRules", new Rule7(analysis).check());
      sliceAnalysisReport.add("cryptoRules", new Rule8(analysis).check());
      sliceAnalysisReport.add("cryptoRules", new Rule9(analysis).check());
      sliceAnalysisReport.add("cryptoRules", new Rule10(analysis).check());
      sliceAnalysisReport.add("cryptoRules", new Rule11(analysis).check());
      sliceAnalysisReport.add("cryptoRules", new Rule12(analysis).check());
      sliceAnalysisReport.add("cryptoRules", new Rule13(analysis).check());
      sliceAnalysisReport.add("cryptoRules", new Rule14(analysis).check());
    } catch (DetectionLogicError e) {
      throw new AnalysisException(e);
    }

    analysis.getReport().add("sliceAnalysis", sliceAnalysisReport.render());

    return true;
  }
}
