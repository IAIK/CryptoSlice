package at.tugraz.iaik.cryptoslice.utils.xml;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.xml.sax.SAXException;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.dom.DOMSource;
import javax.xml.validation.Schema;
import javax.xml.validation.SchemaFactory;
import javax.xml.validation.Validator;
import java.io.File;
import java.io.IOException;
import java.util.Set;
import java.util.TreeSet;

public abstract class XMLDataSource<T> {
  protected Logger LOGGER = LoggerFactory.getLogger(getClass());

  /**
   * The path to the XML file that should be read into a DOM and passed to <em>doParse</em>
   */
  protected String dataFile;

  /**
   * The path to the XML-Schema file that should be used to validate <em>dataFile</em>
   */
  protected String schemaFile;

  protected abstract Set<T> doParse(Document data);

  public Set<T> getData() {
    Set<T> patterns = new TreeSet<T>();
    File patternFile = new File(this.dataFile);
    File schemaFile = new File(this.schemaFile);
    Document data;
    try {
      data = readXMLFile(patternFile);
      if(schemaFile.exists() && schemaFile.canRead())
      {
        LOGGER.trace("Validating additional configuration...");
        Document schema = readXMLFile(schemaFile);
        if (isValid(data, schema)) {
          LOGGER.trace("Additional configuration valid.");
        } else {
          LOGGER.warn("Configuration file invalid! This may cause errors down the line");
        }
      } else {
        LOGGER.warn("No XML-Schema was found at " + schemaFile + ". Invalid additional configuration will not be detected!");
      }

      patterns = doParse(data);
    } catch (InvalidXMLException e) {
      LOGGER.error("Problem reading additional configuration " + patternFile.getAbsolutePath(), e);
    }

    return patterns;
  }

  private Document readXMLFile(File file) throws InvalidXMLException {
    Document xmlFile;

    try {
      DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
      factory.setNamespaceAware(true);
      DocumentBuilder builder;
      builder = factory.newDocumentBuilder();
      xmlFile = builder.parse(file);
    } catch (ParserConfigurationException | SAXException | IOException e) {
      throw new InvalidXMLException(e);
    }

    return xmlFile;
  }

  private boolean isValid(Document xmlDocument, Document xmlSchema) {
    boolean valid = false;

    try {
      DOMSource xmlSource = new DOMSource(xmlDocument);
      DOMSource schemaSource = new DOMSource(xmlSchema);
      SchemaFactory schemaFactory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
      Schema schema = schemaFactory.newSchema(schemaSource);
      Validator validator = schema.newValidator();
      validator.validate(xmlSource);
      valid = true;
    } catch (SAXException e) {
      LOGGER.warn("Validation error",e);
    } catch (IOException e) {
      // do nothing valid=false is failsafe default.
    }

    return valid;
  }
}
