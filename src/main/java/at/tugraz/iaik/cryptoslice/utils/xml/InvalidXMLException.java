package at.tugraz.iaik.cryptoslice.utils.xml;

public class InvalidXMLException extends Exception {

  private static final long serialVersionUID = 20907095841963391L;

  public InvalidXMLException(String message) {
    super(message);
  }

  public InvalidXMLException(Throwable cause) {
    super(cause);
  }

  public InvalidXMLException(String message, Throwable cause) {
    super(message, cause);
  }
}