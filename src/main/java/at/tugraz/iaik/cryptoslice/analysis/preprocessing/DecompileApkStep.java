package at.tugraz.iaik.cryptoslice.analysis.preprocessing;

import at.tugraz.iaik.cryptoslice.analysis.Analysis;
import at.tugraz.iaik.cryptoslice.analysis.AnalysisException;
import at.tugraz.iaik.cryptoslice.analysis.Step;
import at.tugraz.iaik.cryptoslice.application.Application;
import at.tugraz.iaik.cryptoslice.utils.config.ConfigHandler;
import at.tugraz.iaik.cryptoslice.utils.config.ConfigKeys;
import brut.androlib.AndrolibException;
import brut.androlib.ApkDecoder;
import brut.androlib.err.CantFindFrameworkResException;
import brut.androlib.err.InFileNotFoundException;
import brut.androlib.err.OutDirExistsException;
import brut.directory.DirectoryException;
import org.apache.commons.io.FileUtils;

import java.io.File;
import java.io.IOException;

// Decode the .apk file
public class DecompileApkStep extends Step {
  private static final Object MUTEX = new Object();

  public DecompileApkStep(boolean enabled) {
    this.name = "Decompile APK";
    this.enabled = enabled;
  }

  public boolean doProcessing(Analysis analysis) throws AnalysisException {
    Application app = analysis.getApp();

    File apk = app.getApkFile();
    File decompiledContentDir = app.getBytecodeDecompiledDirectory();

    // If activated, do not re-decompile already decompiled .apk files
    if (ConfigHandler.getInstance().getBooleanConfigValue(ConfigKeys.ANALYSIS_DECOMPILE_OMITEXISTING) &&
        app.getSmaliDirectory() != null && app.getSmaliDirectory().isDirectory() &&
        app.getSmaliDirectory().list().length > 0) {
      LOGGER.info("Using existing decompiled code from " + decompiledContentDir.getAbsolutePath());
      return true;
    }

    try {
      LOGGER.info("Decoding extracted content to " + decompiledContentDir.getAbsolutePath());
      decode(apk, decompiledContentDir, app.getBytecodeDirectory().getAbsolutePath());
    } catch (Exception e1) {
      throw new AnalysisException(e1);
    }

    return true;
  }

  private void decode(File apk, File destination, String frameworkDir) throws AnalysisException {
    synchronized(MUTEX){
      ApkDecoder decoder = new ApkDecoder();

      try {
        decoder.setForceDelete(true);
        decoder.setOutDir(destination);
        decoder.setApkFile(apk);
        decoder.setFrameworkDir(frameworkDir);
        decoder.setAnalysisMode(true, false); // decode resources with original API level

        /*if (XMLTPatternSource.getInstance().isForwardPatternProvided())
          decoder.setDecodeResources((short) 0x0101); // DECODE_RESOURCES_FULL, default value of Apktool
        else
          decoder.setDecodeResources((short) 0x0100); // DECODE_RESOURCES_NONE*/

        try {
          decoder.decode();
        } catch (DirectoryException e) {
          throw new AnalysisException(e);
        }

        // Extract the manifest file, because disabling decoding resource also disables decoding of the manifest file
        /*AndrolibResources res = new AndrolibResources();
        ExtFile apkFile = new ExtFile(apk);
        res.decodeManifest(res.getResTable(apkFile, true), apkFile, destination);*/

        // Merge the classes of multiple classes.dex files into one smali folder
        if (decoder.hasMultipleSources()) {
          File[] smaliDirs = destination.listFiles((d, name) -> name.startsWith("smali_"));
          for (File smaliDir : smaliDirs) {
            File destDir = new File(destination, "smali");
            boolean rename = smaliDir.renameTo(destDir);
            if (!rename) {
              FileUtils.copyDirectory(smaliDir, destDir, true);
              FileUtils.deleteDirectory(smaliDir);
            }
          }
        }

      } catch (OutDirExistsException ex) {
        LOGGER.error("Destination directory (" + destination.getAbsolutePath() + ") " + ") already exists.");
        throw new AnalysisException(ex);
      } catch (InFileNotFoundException ex) {
        LOGGER.error("Input file (" + apk.getAbsolutePath() + ") was not found or was not readable.");
        throw new AnalysisException(ex);
      } catch (CantFindFrameworkResException ex) {
        LOGGER.error("Can't find framework resources for package of id: " + ex.getPkgId() +
            ". You must install proper framework files, see project website for more info.");
        throw new AnalysisException(ex);
      } catch (IOException ex) {
        LOGGER.error("Could not modify file. Please ensure you have the permission.");
        throw new AnalysisException(ex);
      } catch (AndrolibException ex) {
        throw new AnalysisException(ex);
      }
    }
  }
}
