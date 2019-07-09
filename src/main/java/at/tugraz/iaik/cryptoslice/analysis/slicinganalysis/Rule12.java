package at.tugraz.iaik.cryptoslice.analysis.slicinganalysis;

import at.tugraz.iaik.cryptoslice.analysis.Analysis;
import at.tugraz.iaik.cryptoslice.analysis.slicing.*;
import at.tugraz.iaik.cryptoslice.application.CodeLine;
import at.tugraz.iaik.cryptoslice.application.DetectionLogicError;
import at.tugraz.iaik.cryptoslice.application.instructions.Constant;
import at.tugraz.iaik.cryptoslice.application.methods.Method;
import at.tugraz.iaik.cryptoslice.utils.PathFinder;
import com.google.common.base.Predicate;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.Iterables;
import com.google.common.collect.Multimap;
import org.stringtemplate.v4.ST;

import java.util.*;

public class Rule12 extends CryptoRule {
  Rule12(Analysis analysis) {
    super(analysis);
  }

  @Override
  public String check() throws DetectionLogicError {
    LOGGER.debug("\n\n## Checking Rule 12: Detect HTTP Basic Authentication");
    ruleReport.addAggr("ruleHead.{number, title}", 12, "Detect HTTP Basic Authentication");
    ruleReport.add("abortMsg", "No suitable calls detected!");

    doHttpUrlConnection();
    doApacheHttpAndSpringFramework();
    doAndroidVolley();
    doUsernamePasswordCredentials();

    return ruleReport.render();
  }

  /**
   * Backtrack HttpURLConnection->setRequestProperty("Authorization", "basic " + Base64.encode("username:password".getBytes()));
   * 1. parameter has to be "Authorization".
   * 2. parameter can be an assembled string with the basic auth data, e.g.:
   * String basicAuth = "Basic " + new String(Base64.encode("user:pass".getBytes(),Base64.NO_WRAP ));
   */
  private void doHttpUrlConnection() throws DetectionLogicError {
    SlicerBackward slicer = new SlicerBackward(analysis.getApp(), searchIds);
    SlicingPatternBT pattern1 = new SlicingPatternBT("java/net/HttpURLConnection", "setRequestProperty", null, 0, "");
    SlicingCriterion criterion = new SlicingCriterion(pattern1);
    slicer.startSearch(criterion);

    if (criterion.getSliceConstants().isEmpty()) {
      LOGGER.info("\nHttpURLConnection: No HttpURLConnection->setRequestProperty() call found!");
      return;
    }

    for (Integer searchId : criterion.getSliceConstants().keySet()) {
      CodeLine startLine = searchIds.get(searchId);
      LOGGER.debug("\nFound HttpURLConnection->setRequestProperty() in method {} in line {}",
          startLine.getMethod().getReadableJavaName(), startLine.getLineNr());

      ST basicAuthReport = analysis.getReport().getTemplate("Rule12_BasicAuth");
      basicAuthReport.addAggr("info.{method, codeline, type}", startLine.getMethod().getReadableJavaName(),
          startLine.getLineNr(), "HttpURLConnection->setRequestProperty");

      Collection<Constant> constants = criterion.getSliceConstants().get(searchId);
      boolean hasAuth = constants.stream().anyMatch(constant -> constant.getValue().contains("uthorization")); // read: [A/a]uthorization
      if (!hasAuth) {
        LOGGER.debug("No authorization header found!");
        basicAuthReport.add("abortMsg", "No authorization header found!");
        ruleReport.add("searchIds", basicAuthReport);
        continue;
      }

      List<CodeLine> searchIds2 = new ArrayList<>();
      SlicerBackward slicer2 = new SlicerBackward(analysis.getApp(), searchIds2);

      // Track the second parameter: HttpURLConnection->setRequestProperty("Authorization", X);
      SlicingCriterion criterion2 = new SlicingCriterion(new SlicingPatternBT(startLine, 1));
      slicer2.startSearch(criterion2);

      if (criterion2.getSliceConstants().isEmpty()) {
        LOGGER.debug("Error: The authorization value uses no constant values!");
        basicAuthReport.add("abortMsg", "The authorization value uses no constant values!");
        ruleReport.add("searchIds", basicAuthReport);
        continue;
      }

      // Extract and filter the path endpoints
      Set<SliceNode> leafs = PathFinder.getLeafs(Iterables.get(criterion2.getSliceTrees().values(), 0));
      for (SliceNode node : rankNodes(leafs, EnumSet.of(FILTER.ALLOW_STRING))) {
        Constant constant = node.getConstant();
        LOGGER.info("Possible User/Pw combination: {}", constant);
        basicAuthReport.add("userPw", stripEnclosingQuotes(constant.getValue()));
      }

      ruleReport.add("searchIds", basicAuthReport.render());
    }
  }

  /**
   * HttpGet / HttpPost:
   * - backtrack HttpGet;->setHeader("Authorization", "Basic "+Base64.encodeBytes("login:password".getBytes()));
   * and all other classes, derived from AbstractHttpMessage
   * http://hc.apache.org/httpcomponents-core-ga/httpcore/apidocs/org/apache/http/message/AbstractHttpMessage.html
   */
  private void doApacheHttpAndSpringFramework() throws DetectionLogicError {
    ImmutableList<SlicingPatternBT> patterns = ImmutableList.of(
        new SlicingPatternBT("org/apache/http/client/methods/HttpGet", "setHeader", "Ljava/lang/String;Ljava/lang/String;", 0, ""),
        new SlicingPatternBT("org/apache/http/client/methods/HttpGet", "addHeader", "Ljava/lang/String;Ljava/lang/String;", 0, ""),
        new SlicingPatternBT("org/apache/http/client/methods/HttpPost", "setHeader", "Ljava/lang/String;Ljava/lang/String;", 0, ""),
        new SlicingPatternBT("org/apache/http/client/methods/HttpPost", "addHeader", "Ljava/lang/String;Ljava/lang/String;", 0, ""),
        new SlicingPatternBT("org/apache/http/client/methods/HttpUriRequest", "setHeader", "Ljava/lang/String;Ljava/lang/String;", 0, ""),
        new SlicingPatternBT("org/apache/http/client/methods/HttpUriRequest", "addHeader", "Ljava/lang/String;Ljava/lang/String;", 0, ""),
        new SlicingPatternBT("org/apache/http/HttpRequest", "addHeader", "Ljava/lang/String;Ljava/lang/String;", 0, ""),
        new SlicingPatternBT("org/apache/http/HttpRequest", "setHeader", "Ljava/lang/String;Ljava/lang/String;", 0, ""),
        new SlicingPatternBT("org/apache/http/HttpMessage", "addHeader", "Ljava/lang/String;Ljava/lang/String;", 0, ""),
        new SlicingPatternBT("org/apache/http/HttpMessage", "setHeader", "Ljava/lang/String;Ljava/lang/String;", 0, ""),
        new SlicingPatternBT("org/apache/http/message/BasicHttpRequest", "addHeader", "Ljava/lang/String;Ljava/lang/String;", 0, ""),
        new SlicingPatternBT("org/apache/http/message/BasicHttpRequest", "setHeader", "Ljava/lang/String;Ljava/lang/String;", 0, ""),
        new SlicingPatternBT("org/apache/http/message/AbstractHttpMessage", "addHeader", "Ljava/lang/String;Ljava/lang/String;", 0, ""),
        new SlicingPatternBT("org/apache/http/message/AbstractHttpMessage", "setHeader", "Ljava/lang/String;Ljava/lang/String;", 0, ""),
        new SlicingPatternBT("org/springframework/http/HttpHeaders", "add", "Ljava/lang/String;Ljava/lang/String;", 0, ""),
        new SlicingPatternBT("org/springframework/http/HttpHeaders", "set", "Ljava/lang/String;Ljava/lang/String;", 0, "")
    );

    SlicingCriterion criterion = new SlicingCriterion();
    SlicerBackward slicer = new SlicerBackward(analysis.getApp(), searchIds);
    for (SlicingPatternBT pattern : patterns) {
      criterion.setPattern(pattern);
      slicer.startSearch(criterion);
    }

    if (criterion.getSliceConstants().isEmpty()) {
      LOGGER.info("\nApache HTTP and Spring framework: No header call found!");
      return;
    }

    for (Integer searchId : criterion.getSliceConstants().keySet()) {
      CodeLine startLine = searchIds.get(searchId);
      LOGGER.debug("\nFound {}->{} in method {} in line {}", startLine.getInstruction().getCalledClassName(),
          startLine.getInstruction().getCalledMethod(), startLine.getMethod().getReadableJavaName(),
          startLine.getLineNr());

      ST basicAuthReport = analysis.getReport().getTemplate("Rule12_BasicAuth");
      basicAuthReport.addAggr("info.{method, codeline, type}", startLine.getMethod().getReadableJavaName(),
          startLine.getLineNr(), "Apache HTTP and Spring framework");

      Collection<Constant> constants = criterion.getSliceConstants().get(searchId);
      boolean hasAuth = constants.stream().anyMatch(constant -> constant.getValue().contains("uthorization")); // read: [A/a]uthorization
      if (!hasAuth) {
        LOGGER.debug("No authorization header found!");
        basicAuthReport.add("abortMsg", "No authorization header found!");
        ruleReport.add("searchIds", basicAuthReport);
        continue;
      }

      List<CodeLine> searchIds2 = new ArrayList<>();
      SlicerBackward slicer2 = new SlicerBackward(analysis.getApp(), searchIds2);

      // Track the second parameter: HttpGet->setHeader("Authorization", X);
      SlicingCriterion criterion2 = new SlicingCriterion(new SlicingPatternBT(startLine, 1));
      slicer2.startSearch(criterion2);

      if (criterion2.getSliceConstants().isEmpty()) {
        LOGGER.debug("Error: The authorization value uses no constant values!");
        basicAuthReport.add("abortMsg", "The authorization value uses no constant values!");
        ruleReport.add("searchIds", basicAuthReport);
        continue;
      }

      // Extract and filter the path endpoints
      Set<SliceNode> leafs = PathFinder.getLeafs(Iterables.get(criterion2.getSliceTrees().values(), 0));
      for (SliceNode node : rankNodes(leafs, EnumSet.of(FILTER.ALLOW_STRING))) {
        Constant constant = node.getConstant();
        LOGGER.info("Possible User/Pw combination: {}", constant);
        basicAuthReport.add("userPw", stripEnclosingQuotes(constant.getValue()));
      }

      ruleReport.add("searchIds", basicAuthReport.render());
    }
  }

  /*
   * For BasicAuth the class com.android.volley.Request or a derivative, such as
   * android/volley/toolbox/StringRequest or ImageRequest, is used and the method getHeaders gets overridden.
   *
   * Strategy:
   * 1. Look for getHeaders()Ljava/util/Map; methods
   * Basically, they can extend from any class in 2nd or 3rd order (not necessarly deduced from Volley).
   *
   * 2. Track credentials:
   * a) First approach:
   * Track invoke-interface {vX, vX, vX}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
   * Problem: What if Map;->put is called in a different method (not getHeaders) and sets a member variable,
   * returned by getHeaders? We would find no invocation of Map;->put by looking only in getHeaders().
   * b) Second approach:
   * Track back the return value of getHeaders since it definitely contains the credentials.
   * Within the slice we isolate all paths from Map;->put to leaf nodes and verify if credentials are added.
   */
  private void doAndroidVolley() throws DetectionLogicError {
    SlicerBackward slicer = new SlicerBackward(analysis.getApp(), searchIds);
    SlicingPatternBT pattern1 = new SlicingPatternBT("*", "getHeaders", null, 0, "", "Ljava/util/Map;");

    SlicingCriterion criterion = new SlicingCriterion(pattern1);
    slicer.startSearch(criterion);

    if (criterion.getSliceConstants().isEmpty()) {
      LOGGER.info("\nAndroid Volley: No suitable getHeaders() methods found!");
      return;
    }

    // For each getHeaders() search result
    for (Integer searchId : criterion.getSliceConstants().keySet()) {
      CodeLine startLine = searchIds.get(searchId);
      LOGGER.debug("\nFound method {} in line {}", startLine.getMethod().getReadableJavaName(), startLine.getLineNr());

      ST basicAuthReport = analysis.getReport().getTemplate("Rule12_BasicAuth");
      basicAuthReport.addAggr("info.{method, codeline, type}", startLine.getMethod().getReadableJavaName(),
          startLine.getLineNr(), "Android Volley (getHeaders)");

      // Look for  [A/a]uthorization constants and abort if none are found
      Collection<Constant> constants = criterion.getSliceConstants().get(searchId);
      boolean containsAuthorization = constants.stream().anyMatch(constant -> constant.getValue().contains("uthorization")); // read: [A/a]uthorization
      if (!containsAuthorization) {
        LOGGER.debug("No authorization header found!");
        basicAuthReport.add("abortMsg", "No authorization header found!");
        ruleReport.add("searchIds", basicAuthReport);
        continue;
      }

      SliceTree tree = criterion.getSliceTrees().get(searchId);
      Multimap<Method, SliceNode> sliceNodes = tree.getSliceNodes();

      // Get all Map->put() nodes from the current getHeaders() slice
      Iterable<SliceNode> mapPutNodes = Iterables.filter(sliceNodes.values(), new Predicate<SliceNode>() {
        public boolean apply(SliceNode arg) {
          return (arg.getConstant() != null && arg.getConstant().getValue() != null &&
              arg.getConstant().getValue().startsWith("java/util/Map->put("));
        }
      });

      // Analyze each Map->put() call
      for (SliceNode mapPutNode : mapPutNodes) {
        List<SliceNode> credentials = new ArrayList<>();
        containsAuthorization = false; // Map->put(Key, ..) is not necessarily "Authorization"
        List<List<SliceNode>> paths = PathFinder.extractAllPathsToLeafs(tree, mapPutNode);

        // We have multiple paths since (at least) Map->put has a key and a value path
        for (List<SliceNode> path : paths) {
          // Looking at the leaf node is probably not enough. At least not, if the credentials come in later.
          credentials = rankNodes(path, EnumSet.of(FILTER.ALLOW_STRING));

          for (SliceNode leaf : credentials) {
            Constant constant = leaf.getConstant();
            if (constant.getValue().contains("uthorization")) {
              containsAuthorization = true;
            }
          }
        }

        if (containsAuthorization) {
          for (SliceNode node : rankNodes(credentials, EnumSet.of(FILTER.ALLOW_STRING))) {
            Constant constant = node.getConstant();
            LOGGER.info("Possible User/Pw combination: {}", constant);
            basicAuthReport.add("userPw", stripEnclosingQuotes(constant.getValue()));
          }
        }
      }

      ruleReport.add("searchIds", basicAuthReport.render());
    }
  }

  /**
   * 4. Apache Http mit Credentials Provider:
   * http://hc.apache.org/httpcomponents-client-ga/tutorial/html/authentication.html
   * CredentialsProvider credProvider = new BasicCredentialsProvider();
   * credProvider.setCredentials(new AuthScope(AuthScope.ANY_HOST, AuthScope.ANY_PORT), new UsernamePasswordCredentials("YOUR USER NAME HERE", "YOUR PASSWORD HERE"));
   * DefaultHttpClient http = new DefaultHttpClient();
   * http.setCredentialsProvider(credProvider);
   */
  private void doUsernamePasswordCredentials() throws DetectionLogicError {
    SlicerBackward slicer = new SlicerBackward(analysis.getApp(), searchIds);
    SlicingPatternBT pattern1 = new SlicingPatternBT("org/apache/http/auth/UsernamePasswordCredentials", "<init>", null, 0, "");
    SlicingCriterion criterion = new SlicingCriterion(pattern1);
    slicer.startSearch(criterion);

    if (criterion.getSliceConstants().isEmpty()) {
      LOGGER.info("\nNo UsernamePasswordCredentials() call found!");
      return;
    }

    for (Integer searchId : criterion.getSliceConstants().keySet()) {
      CodeLine startLine = searchIds.get(searchId);
      LOGGER.debug("\nFound UsernamePasswordCredentials() in method {} in line {}",
          startLine.getMethod().getReadableJavaName(), startLine.getLineNr());

      ST basicAuthReport = analysis.getReport().getTemplate("Rule12_BasicAuth");
      basicAuthReport.addAggr("info.{method, codeline, type}", startLine.getMethod().getReadableJavaName(),
          startLine.getLineNr(), "UsernamePasswordCredentials");

      Set<SliceNode> usernameLeafs = PathFinder.getLeafs(criterion.getSliceTrees().get(searchId));

      // Output usernamePassword combination if UsernamePasswordCredentials takes only one parameter
      String paramSpec = new String(startLine.getInstruction().getCalledClassAndMethodWithParameter()[2]);
      if (paramSpec.equals("Ljava/lang/String;")) {
        for (SliceNode node : rankNodes(usernameLeafs, EnumSet.of(FILTER.ALLOW_STRING))) {
          Constant constant = node.getConstant();
          LOGGER.info("Possible User/Pw combination: {}", constant);
          basicAuthReport.add("userPw", stripEnclosingQuotes(constant.getValue()));
        }
        continue;
      }

      // Track the password parameter: UsernamePasswordCredentials("Username", X);
      SlicingCriterion criterion2 = new SlicingCriterion(new SlicingPatternBT(startLine, 1));
      List<CodeLine> searchIds2 = new ArrayList<>();
      SlicerBackward slicer2 = new SlicerBackward(analysis.getApp(), searchIds2);
      slicer2.startSearch(criterion2);

      Set<SliceNode> passwordLeafs = PathFinder.getLeafs(Iterables.get(criterion2.getSliceTrees().values(), 0));

      LOGGER.info("Probable usernames:");
      for (SliceNode username : rankNodes(usernameLeafs, EnumSet.of(FILTER.ALLOW_STRING))) {
        Constant constant = username.getConstant();
        LOGGER.info("{}", constant);
        basicAuthReport.add("user", stripEnclosingQuotes(constant.getValue()));
      }

      LOGGER.info("Probable passwords:");
      for (SliceNode password : rankNodes(passwordLeafs, EnumSet.of(FILTER.ALLOW_STRING))) {
        Constant constant = password.getConstant();
        LOGGER.info("{}", constant);
        basicAuthReport.add("pw", stripEnclosingQuotes(constant.getValue()));
      }

      ruleReport.add("searchIds", basicAuthReport.render());
    }
  }
}
