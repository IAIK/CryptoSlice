package at.tugraz.iaik.cryptoslice.analysis;

import at.tugraz.iaik.cryptoslice.utils.FileList;
import com.github.fge.largetext.LargeText;
import com.github.fge.largetext.LargeTextException;
import com.github.fge.largetext.LargeTextFactory;
import com.google.common.collect.*;

import java.io.File;
import java.io.IOException;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

public class SecretScanStep extends Step {
  /**
   * References:
   * https://github.com/Yelp/detect-secrets
   * https://github.com/dxa4481/truffleHog/blob/dev/scripts/searchOrg.py
   * https://www.ndss-symposium.org/wp-content/uploads/2019/02/ndss2019_04B-3_Meli_paper.pdf
   */
  private static final ImmutableMap<String, Pattern> SECRETS = ImmutableMap.<String, Pattern> builder()
      // Social Media
      .put("Facebook Access Token", Pattern.compile("EAACEdEose0cBA[0-9A-Za-z]+"))
      .put("Google API Key", Pattern.compile("AIza[0-9A-Za-z\\-_]{35}"))
      .put("Google OAuth ID", Pattern.compile("[0-9]+-[0-9A-Za-z_]{32}\\.apps\\.googleusercontent\\.com"))
      .put("Picatic", Pattern.compile("sk_live_[0-9a-z]{32}"))
      .put("Slack Access Token", Pattern.compile("(xox[p|b|o|a]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32})"))
      .put("Twitter Access Token", Pattern.compile("[1-9][0-9]+-[0-9a-zA-Z]{40}"))
      // Finance
      .put("Amazon MWS Auth Token", Pattern.compile("amzn\\.mws\\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"))
      .put("PayPal Braintree", Pattern.compile("access_token\\$production\\$[0-9a-z]{16}\\$[0-9a-f]{32}"))
      .put("Square Access Token", Pattern.compile("sq0atp-[0-9A-Za-z\\-_]{22}"))
      .put("Square OAuth Secret", Pattern.compile("sq0csp-[0-9A-Za-z\\-_]{43}"))
      .put("Stripe Standard API Key", Pattern.compile("sk_live_[0-9a-zA-Z]{24}"))
      .put("Stripe Restricted API Key", Pattern.compile("rk_live_[0-9a-zA-Z]{24}"))
      // Communications
      .put("MailChimp API Key", Pattern.compile("[0-9a-f]{32}-us[0-9]{1,2}"))
      .put("MailGun API Key", Pattern.compile("key-[0-9a-zA-Z]{32}"))
      .put("Twilio API Key", Pattern.compile("SK[0-9a-fA-F]{32}"))
      // IaaS
      .put("Amazon AWS Access Key ID", Pattern.compile("AKIA[0-9A-Z]{16}"))
      // Misc
      .put("DSA Private Key", Pattern.compile("-----BEGIN DSA PRIVATE KEY-----"))
      .put("EC Private Key", Pattern.compile("-----BEGIN EC PRIVATE KEY-----"))
      .put("Generic Private Key", Pattern.compile("-----BEGIN PRIVATE KEY-----"))
      .put("JSON Web Token", Pattern.compile("eyJ[A-Za-z0-9-_=]+\\.[A-Za-z0-9-_=]+\\.?[A-Za-z0-9-_.+/=]*?"))
      .put("OpenSSH Private Key", Pattern.compile("-----BEGIN OPENSSH PRIVATE KEY-----"))
      .put("Password in URL", Pattern.compile("[a-zA-Z]{3,10}://[^/\\s:@]{3,20}:[^/\\s:@]{3,20}@.{1,100}[\"'\\s]"))
      .put("PGP Private Key", Pattern.compile("-----BEGIN PGP PRIVATE KEY-----"))
      .put("RSA Private Key", Pattern.compile("-----BEGIN RSA PRIVATE KEY-----"))
      .build();

  private static final ImmutableTable<String, String, Pattern> PARALLEL_SECRETS = ImmutableTable.<String, String, Pattern>builder()
      .put("Amazon AWS Access Key ID", "Client Secret", Pattern.compile("[0-9a-zA-Z/+=]{40}"))
      //.put("Amazon MWS Auth Token", "AWS Client ID", Pattern.compile("AKIA[0-9A-Z]{16}"))
      .put("Amazon MWS Auth Token", "AWS Secret Key", Pattern.compile("[0-9a-zA-Z/+=]{40}"))
      .put("Google OAuth ID", "OAuth Secret", Pattern.compile("[a-zA-Z0-9\\-_]{24}"))
      .put("Google OAuth ID", "OAuth Auth Code", Pattern.compile("4/[0-9A-Za-z\\-_]+"))
      .put("Google OAuth ID", "OAuth Refresh Token", Pattern.compile("1/[0-9A-Za-z\\-_]{43}|1/[0-9A-Za-z\\-_]{64}"))
      .put("Google OAuth ID", "OAuth Access Token", Pattern.compile("ya29\\.[0-9A-Za-z\\-_]+"))
      //.put("Google OAuth ID", "API Key", Pattern.compile("AIza[0-9A-Za-z\\-_]{35}"))
      .put("Twilio API Key", "API Secret", Pattern.compile("[0-9a-zA-Z]{32}"))
      .put("Twitter Access Token", "Access Token Secret", Pattern.compile("[0-9a-zA-Z]{45}"))
      .build();

  public SecretScanStep(boolean enabled) {
    this.name = "Secret Scan Step";
    this.enabled = enabled;
  }

  @Override
  public boolean doProcessing(Analysis analysis) throws AnalysisException {
    Table<String, String, File> foundSecrets = TreeBasedTable.create();
    Table<String, String, Set<String>> foundParallelSecrets = HashBasedTable.create();
    FileList allFiles = new FileList(analysis.getApp().getBytecodeDecompiledDirectory(), "*");
    LargeTextFactory factory = LargeTextFactory.defaultFactory();

    for (File file : allFiles.getAllFoundFiles()) {
      try {
        try (final LargeText largeText = factory.load(file.toPath())) {
          try {
            for (Map.Entry<String, Pattern> pattern : SECRETS.entrySet()) {
              final Matcher m = pattern.getValue().matcher(largeText);
              while (m.find()) {
                foundSecrets.put(pattern.getKey(), m.group(), file);

                // Check for parallel secrets in the same file
                for (Map.Entry<String, Pattern> parallelPattern : PARALLEL_SECRETS.row(pattern.getKey()).entrySet()) {
                  final Matcher m1 = parallelPattern.getValue().matcher(largeText);
                  while (m1.find()) {
                    Set<String> possibleSecrets = foundParallelSecrets.get(pattern.getKey(), parallelPattern.getKey());
                    if (possibleSecrets == null)
                      possibleSecrets = new TreeSet<>(Comparator.comparingDouble(SecretScanStep::getShannonEntropy).reversed());

                    possibleSecrets.add(m1.group());

                    foundParallelSecrets.put(pattern.getKey(), parallelPattern.getKey(), possibleSecrets);
                  }
                }
              }
            }
          } catch (LargeTextException e) { // thrown with all binary files
          }
        }
      } catch (IOException e) {
        e.printStackTrace();
      }
    }

    for (Table.Cell<String, String, File> secret : foundSecrets.cellSet()) {
      //System.out.print(secret.getRowKey() + ": " + secret.getColumnKey() + "\n  " + secret.getValue());
      System.out.println(secret.getRowKey() + ": " + secret.getColumnKey());

      // Check for parallel secrets
      for (Map.Entry<String, Set<String>> parallelSecret : foundParallelSecrets.row(secret.getRowKey()).entrySet()) {
        Set<String> possibleSecrets = parallelSecret.getValue();
        System.out.print(secret.getRowKey() + " | " + parallelSecret.getKey());
        if (possibleSecrets.size() < 2) {
          System.out.println(": " + possibleSecrets.iterator().next());
        } else {
          System.out.println(" - Possible candidates:");

          //for (String possibleSecret : possibleSecrets.stream().limit(15).collect(Collectors.toList())) {
          for (String possibleSecret : possibleSecrets) {
            System.out.println("    " + possibleSecret);
            //System.out.printf("  " + possibleSecret + " (entropy: %.12f)\n", getShannonEntropy(possibleSecret));
          }
        }
      }

      System.out.println("  " + secret.getValue());
    }

    return true;
  }

  private static double getShannonEntropy(String s) {
    final Map<Character, Integer> occ = new HashMap<>();

    int n = 0;
    for (int c_ = 0; c_ < s.length(); ++c_) {
      char cx = s.charAt(c_);
      if (occ.containsKey(cx)) {
        occ.put(cx, occ.get(cx) + 1);
      } else {
        occ.put(cx, 1);
      }
      n++;
    }

    double e = 0.0;
    for (Map.Entry<Character, Integer> entry : occ.entrySet()) {
      double p = (double) entry.getValue() / n;
      e += p * Math.log(p) / Math.log(2);
    }

    return -e;
  }
}
