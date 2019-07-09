package at.tugraz.iaik.cryptoslice.utils;

import at.tugraz.iaik.cryptoslice.utils.blacklist.AdChecker;
import at.tugraz.iaik.cryptoslice.utils.blacklist.CryptoLibChecker;

import java.io.File;
import java.io.IOException;
import java.nio.file.*;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.ArrayList;
import java.util.List;

public class FileList {
  public static final String SMALI_FILES = ".smali";
  private final List<File> filterFiles = new ArrayList<File>();

  private class Visitor implements FileVisitor<Path> {
    private final String suffix;

    public Visitor(String suffix) {
      this.suffix = suffix;
    }

    @Override
    public FileVisitResult preVisitDirectory(Path path, BasicFileAttributes attrs) throws IOException {
      boolean hasAd = AdChecker.getInstance().containsAd(path.toAbsolutePath().toString());
      boolean hasCryptoLib = CryptoLibChecker.getInstance().containsCryptoLib(path.toFile().getAbsolutePath());

      return (!hasAd && !hasCryptoLib) ? FileVisitResult.CONTINUE : FileVisitResult.SKIP_SUBTREE;
    }

    @Override
    public FileVisitResult visitFile(Path path, BasicFileAttributes attrs) throws IOException {
      if (suffix.equals("*") || path.getFileName().toString().toLowerCase().endsWith(suffix)) {
        filterFiles.add(path.toFile());
      }

      return FileVisitResult.CONTINUE;
    }

    @Override
    public FileVisitResult visitFileFailed(Path path, IOException exc) throws IOException {
      System.err.println("Error: Cannot visit path " + path);
      return FileVisitResult.CONTINUE;
    }

    @Override
    public FileVisitResult postVisitDirectory(Path path, IOException e) throws IOException {
      return FileVisitResult.CONTINUE;
    }
  }

  /**
   * Scan all files. This method will separate files from ad package on its own,
   * see getAllFoundFiles(boolean includeFilesFromAdPackages).
   *
   * @param startDirectory the directory to scan or a single file to add
   * @param suffix the filter for file names, only files ending with suffix are added
   * (maybe null or empty and the check is NOT case sensitive)
   */
  public FileList(File startDirectory, String suffix) {
    //getAllFilesRecursive(startDirectory, suffix.toLowerCase());

    FileVisitor<Path> fileVisitor = new Visitor(suffix.toLowerCase());
    try {
      Files.walkFileTree(startDirectory.toPath(), fileVisitor);
    } catch (IOException e) {
      e.printStackTrace();
    }
  }

  /**
   * Return all found files.
   *
   * @return all found files matching the filter
   */
  public List<File> getAllFoundFiles() {
    return filterFiles;
  }

  /**
   * Fill the internal vector with all found files. This method calls itself recursively.
   *
   * @param file The file or directory to start with.
   * @param suffix the suffix for files which shall be included
   */
  private void getAllFilesRecursive(File file, String suffix) {
    if (file.isFile() && (suffix.equals("*") || file.getName().toLowerCase().endsWith(suffix))) {
      filterFiles.add(file);
    } else if (file.isDirectory()) {
      File[] listOfFiles = file.listFiles();

      boolean hasAd = AdChecker.getInstance().containsAd(file.getAbsolutePath());
      boolean hasCryptoLib = CryptoLibChecker.getInstance().containsCryptoLib(file.getAbsolutePath());
      if (listOfFiles != null && !hasAd && !hasCryptoLib) {
        for (File g : listOfFiles)
          getAllFilesRecursive(g, suffix);
      }
    }
  }
}
