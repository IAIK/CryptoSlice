package at.tugraz.iaik.cryptoslice.analysis.slicinganalysis;

import at.tugraz.iaik.cryptoslice.analysis.Analysis;
import at.tugraz.iaik.cryptoslice.analysis.slicing.SlicerForward;
import at.tugraz.iaik.cryptoslice.analysis.slicing.SlicingPatternBT;
import at.tugraz.iaik.cryptoslice.application.CodeLine;
import at.tugraz.iaik.cryptoslice.application.DetectionLogicError;
import at.tugraz.iaik.cryptoslice.application.SmaliClass;
import at.tugraz.iaik.cryptoslice.application.SyntaxException;
import at.tugraz.iaik.cryptoslice.application.instructions.InstructionType;
import at.tugraz.iaik.cryptoslice.application.methods.BasicBlock;
import at.tugraz.iaik.cryptoslice.application.methods.Method;
import org.stringtemplate.v4.ST;

import java.util.ArrayList;
import java.util.List;

public class Rule13 extends CryptoRule {
  Rule13(Analysis analysis) {
    super(analysis);
  }

  @Override
  public String check() throws DetectionLogicError {
    LOGGER.debug("\n\n## Checking Rule 13: Detect broken TLS certificate validation");
    ruleReport.addAggr("ruleHead.{number, title}", 13, "Detect broken TLS certificate validation");
    ruleReport.add("abortMsg", "No certificate validator detected!");

    checkTrustManager();
    insecureSocketFactory();
    checkHostnameVerifier();
    allowAllHostnameVerifier();
    webViewClient();

    return ruleReport.render();
  }

  private void checkTrustManager() throws DetectionLogicError {
    SlicerForward slicer = new SlicerForward(analysis.getApp(), searchIds);

    // Examine each checkServerTrusted() occurrence
    SlicingPatternBT checkServerTrusted = new SlicingPatternBT("*", "checkServerTrusted", "[Ljava/security/cert/X509Certificate;Ljava/lang/String;", 0, "");
    List<Method> methodList = slicer.findMethod(checkServerTrusted.getCmp());
    for (Method method : methodList) {
      if (method.getSmaliClass().implementsInterface("javax/net/ssl/TrustManager") ||
          method.getSmaliClass().implementsInterface("javax/net/ssl/X509TrustManager")) {
        LOGGER.info("\nFound custom TrustManager implementation in {}", method.getSmaliClass().getFullClassName(false));

        ST trustManagerReport = analysis.getReport().getTemplate("Rule13_CustomTrustManager");
        trustManagerReport.addAggr("info.{class, type}", method.getSmaliClass().getFullClassName(false),
            "Custom TrustManager (checkServerTrusted)");

        // Check for TrustManager invocations
        SlicingPatternBT trustManagerInvocation = new SlicingPatternBT(method.getSmaliClass().getFullClassName(false), "<init>", "*", 0, "");
        List<CodeLine> invokes = slicer.findInvokes(trustManagerInvocation.getCmp());
        if (invokes.isEmpty()) {
          LOGGER.info("No invocation found!");
        }

        for (CodeLine cl : invokes) {
          LOGGER.info("Invocation found in method {}->{} on line {}", cl.getSmaliClass().getFullClassName(false),
              cl.getMethod().getName(), cl.getLineNr());
          trustManagerReport.addAggr("invokedFrom.{class, method, codeline}", cl.getSmaliClass().getFullClassName(false),
              cl.getMethod().getName(), cl.getLineNr());
        }

        // Check if checkServerTrusted() is non-functional
        if (method.returnsOnlyVoid()) {
          LOGGER.info("ALERT: Non-functional certificate check / TrustManager bypasses validation!");
          trustManagerReport.add("trustStatus", "broken");
        }

        ruleReport.add("searchIds", trustManagerReport);
      }
    }
  }

  private void checkHostnameVerifier() throws DetectionLogicError {
    SlicerForward slicer = new SlicerForward(analysis.getApp(), searchIds);

    // Examine each verify() occurrence
    SlicingPatternBT verify = new SlicingPatternBT("*", "verify", "*", 0, "");
    List<Method> methodList = slicer.findMethod(verify.getCmp());
    for (Method method : methodList) {
      SmaliClass smaliClass = method.getSmaliClass();
      if (smaliClass.implementsInterface("javax/net/ssl/HostnameVerifier") ||
          smaliClass.implementsInterface("org/apache/http/conn/ssl/X509HostnameVerifier") ||
          smaliClass.extendsClass("org/apache/http/conn/ssl/AbstractVerifier") ||
          smaliClass.extendsClass("org/apache/http/conn/ssl/AllowAllHostnameVerifier") ||
          smaliClass.extendsClass("org/apache/http/conn/ssl/BrowserCompatHostnameVerifier") ||
          smaliClass.extendsClass("org/apache/http/conn/ssl/StrictHostnameVerifier")) {
        LOGGER.info("\nFound HostnameVerifier implementation in " + method.getSmaliClass().getFullClassName(false) + " in " + method.getSmaliClass().getFile().getAbsolutePath());

        ST trustManagerReport = analysis.getReport().getTemplate("Rule13_CustomTrustManager");
        trustManagerReport.addAggr("info.{class, type}", method.getSmaliClass().getFullClassName(false),
            "Custom HostnameVerifier (verify)");

        // Check for HostnameVerifier invocations
        SlicingPatternBT hostnameVerifierInvocation = new SlicingPatternBT(method.getSmaliClass().getFullClassName(false), "<init>", "*", 0, "");
        List<CodeLine> invokes = slicer.findInvokes(hostnameVerifierInvocation.getCmp());
        if (invokes.isEmpty()) {
          LOGGER.info("No invocation found!");
        }

        for (CodeLine cl : invokes) {
          LOGGER.info("Invocation found in method {}->{} on line {}", cl.getSmaliClass().getFullClassName(false),
              cl.getMethod().getName(), cl.getLineNr());
          trustManagerReport.addAggr("invokedFrom.{class, method, codeline}", cl.getSmaliClass().getFullClassName(false),
              cl.getMethod().getName(), cl.getLineNr());
        }

        if (method.returnsOnlyVoid() || method.returnsOnlyBoolean()) {
          LOGGER.info("ALERT: Non-functional hostname verification / HostnameVerifier bypasses validation!");
          trustManagerReport.add("trustStatus", "broken");
        }

        ruleReport.add("searchIds", trustManagerReport);
      }
    }
  }

  private void insecureSocketFactory() throws DetectionLogicError {
    SlicerForward slicer = new SlicerForward(analysis.getApp(), searchIds);
    List<CodeLine> insecureFactories = new ArrayList<>();

    // Search for android/net/SSLCertificateSocketFactory->getInsecure() invocations
    SlicingPatternBT getInsecure = new SlicingPatternBT("android/net/SSLCertificateSocketFactory", "getInsecure", "ILandroid/net/SSLSessionCache;", 0, "");
    List<CodeLine> invokes = slicer.findInvokes(getInsecure.getCmp());

    for (CodeLine cl : invokes) {
      LOGGER.info("\nALERT: SSLCertificateSocketFactory->getInsecure invocation found in method {}->{} on line {}",
          cl.getSmaliClass().getFullClassName(false), cl.getMethod().getName(), cl.getLineNr());
      insecureFactories.add(cl);
    }

    if (!insecureFactories.isEmpty()) {
      ST trustManagerReport = analysis.getReport().getTemplate("Rule13_CustomTrustManager");
      trustManagerReport.addAggr("info.{type}", "Insecure SSLSocketFactories");
      trustManagerReport.add("trustStatus", "broken");

      for (CodeLine cl : insecureFactories) {
        trustManagerReport.addAggr("invokedFrom.{class, method, codeline}", cl.getSmaliClass().getFullClassName(false),
            cl.getMethod().getName(), cl.getLineNr());
      }

      ruleReport.add("searchIds", trustManagerReport);
    }
  }

  private void allowAllHostnameVerifier() throws DetectionLogicError {
    List<CodeLine> allowAll = new ArrayList<>();

    for (SmaliClass smaliClass : analysis.getApp().getAllSmaliClasses()) {
      // Skip packaged Apache HTTP libraries
      if (smaliClass.getFullClassName(false).equals("org/apache/http/conn/ssl/SSLSocketFactory")) {
        continue;
      }

      for (CodeLine cl : smaliClass.getAllCodeLines()) {
        String clStr = new String(cl.getLine());

        /*
         * Search
         * - new-instance vX, Lorg/apache/http/conn/ssl/AllowAllHostnameVerifier;
         * - sget-object vX, Lorg/apache/http/conn/ssl/SSLSocketFactory;->ALLOW_ALL_HOSTNAME_VERIFIER
         *   --> returns Lorg/apache/http/conn/ssl/X509HostnameVerifier;
         */
        if ((cl.getInstruction().getType() == InstructionType.NEW_INSTANCE &&
             clStr.endsWith("Lorg/apache/http/conn/ssl/AllowAllHostnameVerifier;")) ||
            (cl.getInstruction().getType() == InstructionType.GET && cl.getLine()[0] == 's' &&
             clStr.contains("Lorg/apache/http/conn/ssl/SSLSocketFactory;->ALLOW_ALL_HOSTNAME_VERIFIER"))) {
          LOGGER.info("\nALERT: AllowAllHostnameVerifier invocation found in method {}->{} on line {}",
              cl.getSmaliClass().getFullClassName(false), cl.getMethod().getName(), cl.getLineNr());
          allowAll.add(cl);
        }
      }
    }

    if (!allowAll.isEmpty()) {
      ST trustManagerReport = analysis.getReport().getTemplate("Rule13_CustomTrustManager");
      trustManagerReport.addAggr("info.{type}", "AllowAllHostnameVerifier");
      trustManagerReport.add("trustStatus", "broken");

      for (CodeLine cl : allowAll) {
        trustManagerReport.addAggr("invokedFrom.{class, method, codeline}", cl.getSmaliClass().getFullClassName(false),
            cl.getMethod().getName(), cl.getLineNr());
      }

      ruleReport.add("searchIds", trustManagerReport);
    }
  }

  /**
   * General handling of certificates with Cordova:
   * https://www.ibm.com/developerworks/community/blogs/mobileblog/entry/apache_cordova_working_with_certificates_on_android?lang=en
   *
   * @throws DetectionLogicError
   */
  private void webViewClient() throws DetectionLogicError {
    SlicerForward slicer = new SlicerForward(analysis.getApp(), searchIds);

    // Examine each onReceivedSslError() occurrence
    SlicingPatternBT onReceivedSslError = new SlicingPatternBT("*", "onReceivedSslError", "Landroid/webkit/WebView;Landroid/webkit/SslErrorHandler;Landroid/net/http/SslError;", 0, "");
    List<Method> methodList = slicer.findMethod(onReceivedSslError.getCmp());
    for (Method method : methodList) {
      if (method.getSmaliClass().extendsClass("android/webkit/WebViewClient")) {
        LOGGER.info("\nFound WebViewClient implementation in {}", method.getSmaliClass().getFullClassName(false));

        ST trustManagerReport = analysis.getReport().getTemplate("Rule13_CustomTrustManager");
        trustManagerReport.addAggr("info.{class, type}", method.getSmaliClass().getFullClassName(false),
            "Custom WebViewClient (onReceivedSslError)");

        // Check for WebViewClient invocations
        SlicingPatternBT webViewInvocation = new SlicingPatternBT(method.getSmaliClass().getFullClassName(false), "<init>", "*", 0, "");
        List<CodeLine> invokes = slicer.findInvokes(webViewInvocation.getCmp());
        if (invokes.isEmpty()) {
          LOGGER.info("No invocation found!");
        }

        for (CodeLine cl : invokes) {
          LOGGER.info("Invocation found in method {}->{} on line {}", cl.getSmaliClass().getFullClassName(false),
              cl.getMethod().getName(), cl.getLineNr());
          trustManagerReport.addAggr("invokedFrom.{class, method, codeline}", cl.getSmaliClass().getFullClassName(false),
              cl.getMethod().getName(), cl.getLineNr());
        }

        // Check if onReceivedSslError() accepts all certificates
        // https://developer.android.com/reference/android/webkit/SslErrorHandler.html
        boolean acceptsAllCerts = false;
        try {
          CodeLine firstCl = BasicBlock.getFirstCodeLine(method.getFirstBasicBlock()).getCodeLine();
          if (firstCl.getInstruction().getType() == InstructionType.INVOKE &&
              new String(firstCl.getLine()).contains("Landroid/webkit/SslErrorHandler;->proceed()V")) {
            acceptsAllCerts = true;
          }
        } catch (SyntaxException e) {
          LOGGER.error(e.getMessage());
        }

        // Check if onReceivedSslError() is non-functional
        if (acceptsAllCerts || method.returnsOnlyVoid()) {
          LOGGER.info("ALERT: Non-functional certificate check / WebViewClient bypasses validation!");
          trustManagerReport.add("trustStatus", "broken");
        } else {
          // Check if the WebViewClient proceeds with the cert anyway in case an error occurred
          for (CodeLine cl : method.getCodeLines()) {
            if (cl.getInstruction().getType() == InstructionType.INVOKE &&
                new String(cl.getLine()).contains("Landroid/webkit/SslErrorHandler;->proceed()V")) {
              LOGGER.info("ALERT: WebViewClient proceeds with (invalid?) certificate despite of SSL error!");
              trustManagerReport.add("trustStatus", "probably broken");
            }
          }
        }

        ruleReport.add("searchIds", trustManagerReport);
      }
    }
  }
}
