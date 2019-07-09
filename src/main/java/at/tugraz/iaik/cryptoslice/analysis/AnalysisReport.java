package at.tugraz.iaik.cryptoslice.analysis;

import at.tugraz.iaik.cryptoslice.utils.config.ConfigHandler;
import at.tugraz.iaik.cryptoslice.utils.config.ConfigKeys;
import com.google.common.xml.XmlEscapers;
import org.apache.commons.io.FileUtils;
import org.stringtemplate.v4.AttributeRenderer;
import org.stringtemplate.v4.ST;
import org.stringtemplate.v4.STGroup;
import org.stringtemplate.v4.STGroupFile;

import java.io.File;
import java.io.IOException;
import java.util.Locale;

public class AnalysisReport {
  private final STGroup group;
  private ST report = null;

  AnalysisReport() {
    group = new STGroupFile(ConfigHandler.getInstance().getConfigValue(ConfigKeys.ANALYSIS_REPORT_TEMPLATE), '$', '$');
    group.registerRenderer(String.class, new XMlEscapeStringRenderer());
    report = group.getInstanceOf("report");
  }

  public ST getTemplate(String name) {
    return group.getInstanceOf(name);
  }

  public void add(String sectionName, String sectionContent) {
    report.add(sectionName, sectionContent);
  }

  public void writeReport(String reportFileName) {
    if (!ConfigHandler.getInstance().getBooleanConfigValue(ConfigKeys.ANALYSIS_DO_REPORT))
      return;

    try {
      File reportFile = new File(ConfigHandler.getInstance().getConfigValue(ConfigKeys.ANALYSIS_REPORT_FOLDER) +
          File.separator + reportFileName + ".xml");
      FileUtils.writeStringToFile(reportFile, report.render(), "UTF-8", false);
    } catch (IOException e) {
      e.printStackTrace();
    }
  }

  @Override
  public String toString() {
    return report.render();
  }

  public static class XMlEscapeStringRenderer implements AttributeRenderer {
    public String toString(Object o, String s, Locale locale) {
      return (String) (s == null ? o : XmlEscapers.xmlAttributeEscaper().escape((String) o));
    }
  }
}
