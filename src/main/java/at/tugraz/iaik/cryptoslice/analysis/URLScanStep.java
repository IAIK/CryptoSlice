package at.tugraz.iaik.cryptoslice.analysis;

import at.tugraz.iaik.cryptoslice.utils.FileList;
import at.tugraz.iaik.cryptoslice.utils.URLPatterns;
import com.github.fge.largetext.LargeText;
import com.github.fge.largetext.LargeTextException;
import com.github.fge.largetext.LargeTextFactory;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.Multimap;
import com.google.common.collect.MultimapBuilder;

import java.io.File;
import java.io.IOException;
import java.util.Collection;
import java.util.regex.Matcher;

// Shows URLs
public class URLScanStep extends Step {
  private static final ImmutableList<String> URL_WHITELIST = ImmutableList.<String> builder()
      .add("apache.org/licenses")
      .add("creativecommons.org/ns")
      .add("www.inkscape.org")
      .add("opensource.org/licenses")
      .add("phonegap.com/ns")
      .add("purl.org")
      .add("schemas.android.com")
      .add("schemas.xmlsoap.org")
      .add("w3.org/")
      .add("web.resource.org")
      .add("www.opengis.net")
      .add("xml.org/sax/")
      .add("xmlpull.org/v1/")
      .build();

  public URLScanStep(boolean enabled) {
    this.name = "URL Step";
    this.enabled = enabled;
  }

  @Override
  public boolean doProcessing(Analysis analysis) throws AnalysisException {
    Multimap<String, File> foundUrls = MultimapBuilder.treeKeys().treeSetValues().build();
    FileList allFiles = new FileList(analysis.getApp().getBytecodeDecompiledDirectory(), "*");
    LargeTextFactory factory = LargeTextFactory.defaultFactory();

    for (File file : allFiles.getAllFoundFiles()) {
      try {
        try (final LargeText largeText = factory.load(file.toPath())) {
          try {
            final Matcher m = URLPatterns.WEB_URL_WITHPREFIX.matcher(largeText);
            while (m.find()) {
              String url = m.group();

              boolean urlIsWhitelisted = false;
              for (String friendlyUrl : URL_WHITELIST) {
                if (url.contains(friendlyUrl)) {
                  urlIsWhitelisted = true;
                  break;
                }
              }

              if (!urlIsWhitelisted) {
                foundUrls.put(url, file);
              }
            }
          } catch (LargeTextException e) { // thrown with all binary files
          }
        }
      } catch (IOException e) {
        e.printStackTrace();
      }
    }

    for (String url : foundUrls.keySet()) {
      Collection<File> files = foundUrls.get(url);
      System.out.println("URL: " + url);
      for (File file : files) {
        System.out.println("     " + file.getAbsolutePath());
      }
    }

    return true;
  }
}
