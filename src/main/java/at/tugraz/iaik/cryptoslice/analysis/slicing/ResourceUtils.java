package at.tugraz.iaik.cryptoslice.analysis.slicing;

import at.tugraz.iaik.cryptoslice.application.Application;
import at.tugraz.iaik.cryptoslice.application.CodeLine;
import at.tugraz.iaik.cryptoslice.application.Field;
import at.tugraz.iaik.cryptoslice.application.SmaliClass;
import at.tugraz.iaik.cryptoslice.application.instructions.Instruction;
import at.tugraz.iaik.cryptoslice.application.instructions.InstructionType;
import at.tugraz.iaik.cryptoslice.application.methods.Method;
import at.tugraz.iaik.cryptoslice.utils.ByteUtils;
import com.google.common.primitives.Bytes;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.filefilter.FileFilterUtils;
import org.apache.commons.io.filefilter.TrueFileFilter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;
import java.io.File;
import java.io.IOException;
import java.util.*;

public class ResourceUtils {
  private static final Logger LOGGER = LoggerFactory.getLogger(ResourceUtils.class);

  public static Map<String, String> findConstForResourceIds(Set<String> resourceIds, Application app) {
    Map<String, String> constantIds = new HashMap<>(); // key: resource ident in XML files, value: constant Id

    // TODO: Save rIdFiles in app and reuse it if needed. Result: Prevent possibly redundant lookups
    Collection<File> rIdFiles = FileUtils.listFiles(app.getSmaliDirectory(), FileFilterUtils.nameFileFilter("R$id.smali"), TrueFileFilter.INSTANCE);
    for (File rIdFile : rIdFiles) {
      SmaliClass sc = app.getSmaliClass(rIdFile);
      if (sc == null) {
        LOGGER.error("Could not find SMALI file for raw file '{}'. SmaliClass object most probably threw an exception" +
            " while parsing it. Ignoring this one.", rIdFile);
        continue;
      }
      List<Field> fields = sc.getAllFields();

      // Check if the R$id file has a <clinit> constructor. Fields could be assigned there.
      Method staticCtor = null;
      for (Method m : sc.getMethods()) {
        if (Arrays.equals(Method.STATIC_CONSTRUCTOR_NAME, m.getName().getBytes())) {
          staticCtor = m;
          break;
        }
      }

      // Check if a field corresponds to a resourceId
      for (Field field : fields) {
        for (String resourceId : resourceIds) {
          String resourceIdCut = resourceId.replace("@+id/", "").replace("@id/", "");

          if (field.getFieldName().equals(resourceIdCut)) {
            byte[] cl = field.getCodeLine().getLine();

            int equalSignIndex = Bytes.indexOf(cl, (byte) '=');
            if (equalSignIndex > 0) {
              String fieldValue = new String(ByteUtils.subbytes(cl, equalSignIndex + 2));
              LOGGER.debug("findConstForResourceId: {} with field value {}", resourceId, fieldValue);
              constantIds.put(resourceId, fieldValue);
            }
            else if (staticCtor != null) { // Field is not final. Check for an initialization within <clinit>.
              LinkedList<CodeLine> clsCtor = staticCtor.getCodeLines();
              for (int i = 0; i < clsCtor.size(); i++) {
                // Try to find a SPUT which writes the field
                Instruction iPut = clsCtor.get(i).getInstruction();
                if (iPut.getType() == InstructionType.PUT &&
                    Arrays.equals(iPut.getResultField()[1], resourceIdCut.getBytes())) {

                  // Look for a CONST line with the value, assigned to the field.
                  CodeLine clConst = clsCtor.get(i-1);
                  Instruction iConst = clConst.getInstruction();
                  if (iConst.getType() == InstructionType.CONST &&
                      Arrays.equals(iConst.getResultRegister(), iPut.getInvolvedRegisters().get(0))) {
                    LinkedList<byte[]> clConstSplitted = Instruction.split(clConst.getLine());
                    String fieldValue = new String(clConstSplitted.get(2));
                    LOGGER.debug("findConstForResourceId: {} with assigned value {}", resourceId, fieldValue);
                    constantIds.put(resourceId, fieldValue);
                  }
                }
              }
            } // else: field is neither final nor statically defined.

            break; // because there may not be field duplicates in 1 file anyway.
          }
        }
      }
    }

    // Check if we need to load public.xml too for further lookups
    boolean checkPublicXml = false;
    for (String resourceId : resourceIds) {
      if (!constantIds.containsKey(resourceId)) {
        checkPublicXml = true;
        break;
      }
    }

    if (checkPublicXml) {
      File xmlFile = new File(app.getBytecodeDecompiledDirectory().getAbsolutePath() + File.separator + "res" +
          File.separator + "values" + File.separator + "public.xml");
      Document doc;

      try {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setNamespaceAware(false); // no Android namespace for xPath!
        DocumentBuilder builder;
        builder = factory.newDocumentBuilder();
        doc = builder.parse(xmlFile);
      } catch (ParserConfigurationException | SAXException | IOException e) {
        LOGGER.error("findConstForResourceId: Error while parsing {}: {}", xmlFile.getAbsolutePath(), e.getMessage());
        return constantIds;
      }

      XPathFactory xPathfactory = XPathFactory.newInstance();
      XPath xPath = xPathfactory.newXPath();

      for (String resourceId : resourceIds) {
        String resourceIdCut = resourceId.replace("@+id/", "").replace("@id/", "");
        String xPathQuery = "//public[@type='id' and @name='" + resourceIdCut + "']/@id";
        try {
          String fieldValue = (String) xPath.evaluate(xPathQuery, doc, XPathConstants.STRING);
          if (fieldValue != null && !fieldValue.isEmpty()) {
            LOGGER.debug("findConstForResourceId: {} with public.xml value {}", resourceId, fieldValue);
            constantIds.put(resourceId, fieldValue);
          }
        } catch (XPathExpressionException xpe) {
          LOGGER.error("findResourceIdForInputType: xPath error: {}", xpe.getMessage());
        }
      }
    }

    return constantIds;
  }

  public static Set<String> findResourceIdsForInputType(String xPathQuery, Application app) {
    Set<String> resourceIds = new HashSet<>();
    String resDir = app.getBytecodeDecompiledDirectory().getAbsolutePath() + File.separator + "res";

    // TODO: Save xmlFiles in app and reuse it if needed. Result: Prevent possibly redundant lookups
    Collection<File> xmlFiles = FileUtils.listFiles(new File(resDir), new String[]{"xml"}, true);
    for (File xmlFile : xmlFiles) {
      // Parse the XML document
      Document doc;

      try {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setNamespaceAware(false); // no Android namespace for xPath!
        DocumentBuilder builder = factory.newDocumentBuilder();
        doc = builder.parse(xmlFile);
      } catch (ParserConfigurationException | SAXException | IOException e) {
        LOGGER.error("findResourceIdForInputType: Error while parsing {}: {}" + xmlFile.getAbsolutePath(), e.getMessage());
        continue;
      }

      // Find the InputType value using xPath
      XPathFactory xPathfactory = XPathFactory.newInstance();
      XPath xPath = xPathfactory.newXPath();

      try {
        NodeList editTextNodes = (NodeList) xPath.evaluate(xPathQuery, doc, XPathConstants.NODESET);
        if (editTextNodes == null)
          continue;

        LOGGER.trace("findResourceIdForInputType: Found {} matching EditText nodes in {}", editTextNodes.getLength(), xmlFile.getName());

        for (int nodeIndex = 0; nodeIndex < editTextNodes.getLength(); nodeIndex++) {
          Element editTextNode = (Element) editTextNodes.item(nodeIndex);
          String editTextId = editTextNode.getAttribute("android:id");
          LOGGER.debug("findResourceIdForInputType: Found field {}", editTextId);
          resourceIds.add(editTextId);
        }
      } catch (XPathExpressionException xpe) {
        LOGGER.error("findResourceIdForInputType: xPath error: {}", xpe.getMessage());
      }
    }

    return resourceIds;
  }

  public static String findStringValueForResourceName(File resDir, String identifier) {
    File stringRes = new File(resDir.getAbsolutePath() + File.separator + "res" + File.separator + "values" +
        File.separator + "strings.xml");

    try {
      DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
      factory.setNamespaceAware(false); // no Android namespace for xPath!
      DocumentBuilder builder = factory.newDocumentBuilder();
      Document doc = builder.parse(stringRes);

      XPathFactory xPathfactory = XPathFactory.newInstance();
      XPath xPath = xPathfactory.newXPath();

      String xPathQuery = "//string[@name='" + identifier + "']";
      try {
        String fieldValue = (String) xPath.evaluate(xPathQuery, doc, XPathConstants.STRING);
        if (fieldValue != null && !fieldValue.isEmpty()) {
          LOGGER.trace("findValueForRName: {} with string.xml value {}", identifier, fieldValue);
          return fieldValue;
        }
      } catch (XPathExpressionException xpe) {
        LOGGER.error("findValueForRName: xPath error: {}", xpe.getMessage());
      }
    } catch (ParserConfigurationException | SAXException | IOException e) {
      LOGGER.error("findValueForRName: Error while parsing {}: {}", stringRes.getAbsolutePath(), e.getMessage());
    }

    return null;
  }

  public static String findResourceNameForResourceId(File resDir, String resourceId) {
    File stringRes = new File(resDir.getAbsolutePath() + File.separator + "res" + File.separator + "values" +
        File.separator + "public.xml");

    try {
      DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
      factory.setNamespaceAware(false); // no Android namespace for xPath!
      DocumentBuilder builder = factory.newDocumentBuilder();
      Document doc = builder.parse(stringRes);

      XPathFactory xPathfactory = XPathFactory.newInstance();
      XPath xPath = xPathfactory.newXPath();

      String xPathQuery = "//public[@id='" + resourceId + "']/@name";
      try {
        String fieldValue = (String) xPath.evaluate(xPathQuery, doc, XPathConstants.STRING);
        if (fieldValue != null && !fieldValue.isEmpty()) {
          LOGGER.trace("findRawResourceNameForResourceId: {} with public.xml value {}", resourceId, fieldValue);
          return fieldValue;
        }
      } catch (XPathExpressionException xpe) {
        LOGGER.error("findRawResourceNameForResourceId: xPath error: {}", xpe.getMessage());
      }
    } catch (ParserConfigurationException | SAXException | IOException e) {
      LOGGER.error("findRawResourceNameForResourceId: Error while parsing {}: {}", stringRes.getAbsolutePath(), e.getMessage());
    }

    return null;
  }
}
