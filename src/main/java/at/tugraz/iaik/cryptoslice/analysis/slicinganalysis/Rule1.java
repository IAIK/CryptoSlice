package at.tugraz.iaik.cryptoslice.analysis.slicinganalysis;

import at.tugraz.iaik.cryptoslice.analysis.Analysis;
import at.tugraz.iaik.cryptoslice.analysis.slicing.SliceNode;
import at.tugraz.iaik.cryptoslice.analysis.slicing.SlicerBackward;
import at.tugraz.iaik.cryptoslice.analysis.slicing.SlicingCriterion;
import at.tugraz.iaik.cryptoslice.analysis.slicing.SlicingPatternBT;
import at.tugraz.iaik.cryptoslice.application.DetectionLogicError;
import at.tugraz.iaik.cryptoslice.application.instructions.Constant;
import com.google.common.base.Predicate;
import com.google.common.collect.ImmutableMultimap;
import com.google.common.collect.ImmutableSet;
import com.google.common.collect.Iterables;
import com.google.common.collect.Multimap;
import org.stringtemplate.v4.ST;

import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

public class Rule1 extends CryptoRule {
  /*
   * Some ciphers have synonyms that can have mode and padding information too.
   *
   * DESede    -> TDEA
   * GOST28147 -> GOST, GOST-28147
   * RC5       -> RC5-32 (Note: RC5-64 is different!)
   * Treefish is offered as Treefish-256, Treefish-512, Treefish-1024.
   */
  private static final ImmutableSet<String> SYMMETRIC_BLOCK_CIPHERS = ImmutableSet.of(
      "AES", "Blowfish", "Camellia", "CAST5", "CAST6", "DES", "DESede", "GOST", "GOST-28147", "GOST28147", "IDEA",
      "Noekeon", "RC2", "RC5", "RC5-32", "RC5-64", "RC6", "Rijndael", "SEED", "Serpent", "Shacal2", "Skipjack", "TDEA",
      "TEA", "Threefish-256", "Threefish-512", "Threefish-1024", "Twofish", "XTEA");

  private static final Multimap<String, String> SYMMETRIC_BLOCK_CIPHERS_ALIAS = new ImmutableMultimap.Builder<String, String>()
      .put("AES", "PBEWITH.+AND.*AES.*")             // PBEWITHSHA1AND128BITAES-CBC-BC
      .put("DES", "PBEWITH.+ANDDES")                 // PBEWITHMD2ANDDES
      .put("DES", "PBEWITH.+ANDDES-.*")              // PBEWITHSHA1ANDDES-CBC
      .put("DESede", "PBEWITH.+ANDDESEDE")           // PBEWITHSHA1ANDDESEDE
      .put("DESede", "PBEWITH.+AND.*KEYTRIPLEDES.*") // PBEWITHSHAAND2-KEYTRIPLEDES-CBC, PBEWITHSHA1AND3-KEYTRIPLEDES-CBC, PBEWithSHAAnd3KeyTripleDES
      .put("DESede", "PBEWITH.+ANDDES(2|3)KEY.*")    // PBEWITHSHAANDDES2KEY-CBC, PBEWITHSHAANDDES3KEY-CBC
      .put("IDEA", "PBEWITH.+ANDIDEA.*")             // PBEWITHSHAANDIDEA, PBEWITHSHAANDIDEA-CBC
      .put("RC2", "PBEWITH.+ANDRC2.*")               // PBEWITHMD2ANDRC2, PBEWITHMD2ANDRC2-CBC
      .put("Twofish", "PBEWITH.+ANDTWOFISH.*")       // PBEWITHSHAANDTWOFISH, PBEWITHSHAANDTWOFISH-CBC
      .build();

  private static final ImmutableSet<String> SYMMETRIC_BLOCK_CIPHERS_MISC = ImmutableSet.of(
      "AESWrap, CAMELLIAWrap", "DESedeWrap", "RC2Wrap", "SEEDWrap", "TDEAWRAP", // WRAP
      "CCM", "GCM");

  private static final ImmutableSet<String> SYMMETRIC_STREAM_CIPHERS = ImmutableSet.of(
      "ARC4", "ChaCha", "Grain128", "Grainv1","HC128", "HC256", "Salsa20", "VMPC", "VMPC-KSA3", "XSalsa20");

  private static final Multimap<String, String> SYMMETRIC_STREAM_CIPHERS_ALIAS = new ImmutableMultimap.Builder<String, String>()
      .put("ARC4", "ARCFOUR")
      .put("ARC4", "RC4")
      .put("ARC4", "PBEWITH.+AND.*RC4")
      .build();

  private static final ImmutableSet<String> ASYMMETRIC_BLOCK_CIPHERS = ImmutableSet.of("DHIES", "ECIES", "ElGamal", "RSA");

  Rule1(Analysis analysis) {
    super(analysis);
  }

  @Override
  public String check() throws DetectionLogicError {
    LOGGER.debug("\n\n## Checking Rule 1: No ECB for encryption");
    ruleReport.addAggr("ruleHead.{number, title}", 1, "No ECB for encryption");

    // Track back the transformation string (parameterIndex 0) of all getInstance overloads.
    SlicingPatternBT pattern = new SlicingPatternBT("javax/crypto/Cipher", "getInstance", null, 0, "");
    SlicingCriterion criterion = new SlicingCriterion(pattern);
    SlicerBackward slicer = new SlicerBackward(analysis.getApp(), searchIds);
    slicer.startSearch(criterion);

    if (criterion.getSliceConstants().isEmpty()) {
      LOGGER.info("Abort: No Cipher instance or no constants found!");
      ruleReport.add("abortMsg", "No Cipher instance or no constants found!");
      return ruleReport.render();
    }

    for (Integer searchId : criterion.getSliceConstants().keySet()) {
      SliceNode startNode = criterion.getSliceTrees().get(searchId).getStartNode();
      LOGGER.info("\nFound Cipher.getInstance() in method " + startNode.getMethod().getReadableJavaName() +
          " in line " + startNode.getCodeLine().getLineNr());

      ST cipherInstanceReport = analysis.getReport().getTemplate("Rule1_CipherInstance");
      cipherInstanceReport.addAggr("info.{method, codeline}", startNode.getMethod().getReadableJavaName(),
          startNode.getCodeLine().getLineNr());

      /*for (Constant constant : criterion.getSliceConstants().get(searchId))
        System.out.println("RAW: " + constant.toString());*/

      // Filter all constants that describe a cipher pattern (can be multiple, in case of if-else statement)
      Iterable<Constant> cipherConstants = Iterables.filter(criterion.getSliceConstants().get(searchId), new Predicate<Constant>() {
        @Override
        public boolean apply(Constant constant) {
          // The cipher has to be a String with non-null value
          return (constant.getVarTypeDescription() != null && constant.getValue() != null &&
              constant.getVarTypeDescription().equals("java/lang/String") && containsCipher(constant.getValue()));
        }
      });

      if (Iterables.isEmpty(cipherConstants)) {
        LOGGER.error("No Cipher transformation string found!");
        ruleReport.add("searchIds", cipherInstanceReport);
        continue;
      }

      // Filter constants that look like mode and padding (i.e. "/ECB/PKCS5Padding")
      Iterable<Constant> cipherAppendices = Iterables.filter(criterion.getSliceConstants().get(searchId), new Predicate<Constant>() {
        @Override
        public boolean apply(Constant constant) {
          return (constant.getVarTypeDescription() != null && constant.getValue() != null &&
              constant.getVarTypeDescription().equals("java/lang/String")) && constant.getValue().matches("(?i)^\"/.+/.+\"$");
        }
      });

      // Filter duplicate cipher names and prefer constants with lower fuzzy level
      Map<String, Constant> ciphers = new HashMap<>();
      for (Constant constant : cipherConstants) {
        Constant mapCipher = ciphers.get(constant.getValue());
        if (mapCipher == null || constant.getFuzzyLevel() < mapCipher.getFuzzyLevel())
          ciphers.put(constant.getValue(), constant);
      }

      /*
       * Cipher output and evaluation if ECB mode is used.
       * For asymmetric ciphers, a mode makes no sense at all and is ignored by all JCEs (i.e. Bouncycastle).
       */
      for (Constant cipherConstant : ciphers.values()) {
        String cipher = cipherConstant.getValue();

        // Check if we found appendices and have a "short" (no mode/padding given) symmetric block ciphers.
        if (!Iterables.isEmpty(cipherAppendices) &&
            searchValuePatternInList(SYMMETRIC_BLOCK_CIPHERS, cipher, "\"$")) {
          for (Constant appendix : cipherAppendices) {
            String cipherAppended = stripEnclosingQuotes(cipher).concat(appendix.getValue().substring(1));
            LOGGER.debug("Cipher transformation (composed): " + cipherAppended);

            // Check if the appendix (mode/padding) uses ECB.
            boolean isECB = false;
            if (appendix.getValue().matches("(?i)^\"/ECB/.+\"$")) {
              isECB = true;
              LOGGER.warn("ALERT: ECB mode is used for encryption! Cipher transformation: " + cipherAppended);
            }

            cipherInstanceReport.addAggr("cipherConstants.{cipher, isECB}", stripEnclosingQuotes(cipherAppended), isECB);
          }

          /*
           * In case there is a modifying if-clause, the used cipher could be "AES" or "AES+appendix".
           * We do not know if the not-appended cipher is also used, so we check the fuzzy level.
           * If it is 0, there is an untainted path Cipher.getInstance() to the cipher -> directly usable, i.e.:
           *   String cipher = "AES";
           *   if (isBouncycastleAvailable)
           *     cipher += "/CBC/PKCS5Padding"; // invokes external method StringBuilder.append() --> fuzzylevel++
           *   Cipher.getInstance(cipher);
           */
          if (cipherConstant.getFuzzyLevel() == 0) {
            LOGGER.debug("Cipher transformation: " + cipher);
            // We need no ECB check here because we already know that the cipherConstant is short and symmetric -> ECB
            LOGGER.warn("ALERT: ECB mode is used for encryption! Cipher transformation: " + cipher);
            cipherInstanceReport.addAggr("cipherConstants.{cipher, isECB}", stripEnclosingQuotes(cipher), true);
          }
        } else {
          LOGGER.debug("Cipher transformation: " + cipher);

          /*
           * Two possibilites for ECB mode:
           * - A symmetric block cipher is used without given mode/padding -> ECB is chosen automatically.
           * - The mode is explicitly specified.
           *
           * --> Look for the value (i.e. "AES") itself or a transformation string with ECB (i.e. "AES/ECB/PKCS5Padding")
           */
          boolean ret = searchValuePatternInList(SYMMETRIC_BLOCK_CIPHERS, cipher, "(/ECB/.+)?\"$");
          boolean isECB = false;
          if (ret) {
            isECB = true;
            LOGGER.warn("ALERT: ECB mode is used for encryption! Cipher transformation: " + cipher);
          }

          cipherInstanceReport.addAggr("cipherConstants.{cipher, isECB}", stripEnclosingQuotes(cipher), isECB);
        }
      }

      ruleReport.add("searchIds", cipherInstanceReport);
    }

    return ruleReport.render();
  }

  private boolean containsCipher(String value) {
    // Look for the value (i.e. "AES") or the value within a transformation string (i.e. "AES/CBC/PKCS5Padding")
    boolean ret = searchValuePatternInList(SYMMETRIC_BLOCK_CIPHERS, value, "(/.+/.+)?\"$");
    if (ret) return true;

    // Look for an alias (but no mode/padding)
    ret = searchValuePatternInList(SYMMETRIC_BLOCK_CIPHERS_ALIAS.values(), value, "\"$");
    if (ret) return true;

    // Remaining ciphers that can not have a transformation string
    ret = searchValuePatternInList(SYMMETRIC_BLOCK_CIPHERS_MISC, value, "\"$");
    if (ret) return true;

    ret = searchValuePatternInList(SYMMETRIC_STREAM_CIPHERS, value, "\"$");
    if (ret) return true;

    ret = searchValuePatternInList(SYMMETRIC_STREAM_CIPHERS_ALIAS.values(), value, "\"$");
    if (ret) return true;

    // Pattern to match DHIESwithAES, DHIES/DHAES/PKCS7Padding), RSA//RAW, RSA/ISO9796-1, RSA/ECB/PKCS1Padding
    ret = searchValuePatternInList(ASYMMETRIC_BLOCK_CIPHERS, value, ".*\"$");

    return ret;
  }

  private boolean searchValuePatternInList(Collection<String> list, String value, String regexSuffix) {
    for (String cipher : list) {
      if (value.matches("(?i)^\"" + cipher + regexSuffix)) { // All strings come quoted!
        LOGGER.trace("Matching pattern " + cipher);
        return true;
      }
    }

    return false;
  }
}
