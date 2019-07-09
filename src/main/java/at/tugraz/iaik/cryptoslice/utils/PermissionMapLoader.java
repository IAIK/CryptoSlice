package at.tugraz.iaik.cryptoslice.utils;

import at.tugraz.iaik.cryptoslice.utils.config.ConfigHandler;
import at.tugraz.iaik.cryptoslice.utils.config.ConfigKeys;
import com.google.common.base.Charsets;
import com.google.common.collect.HashMultimap;
import com.google.common.collect.Multimap;
import com.google.common.io.Files;
import com.google.common.io.LineProcessor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

public class PermissionMapLoader {
  private static final Logger LOGGER = LoggerFactory.getLogger(PermissionMapLoader.class);
  private Multimap<String, List<String>> permissionMap = HashMultimap.create();

  private static class PermissionMapLoaderHolder {
    private static final PermissionMapLoader INSTANCE = new PermissionMapLoader();
  }

  public static PermissionMapLoader getInstance() {
    return PermissionMapLoaderHolder.INSTANCE;
  }

  private PermissionMapLoader() {
    ConfigHandler conf = ConfigHandler.getInstance();

    String dataFile = conf.getConfigValue(ConfigKeys.DATASOURCE_PERMISSIONMAP);
    boolean matchAPICalls = ConfigHandler.getInstance().getBooleanConfigValue(ConfigKeys.ANALYSIS_MATCH_APICALLS);
    if (!matchAPICalls)
      return;

    try {
      permissionMap = Files.asCharSource(new File(dataFile), Charsets.UTF_8).readLines(
          new LineProcessor<Multimap<String, List<String>>>() {
        private final Multimap<String, List<String>> result = HashMultimap.create();

        public boolean processLine(String line) {
          String[] parts = line.trim().split("\t");
          if (parts.length == 1) // Skip invalid lines
            return true;

          String apiCall = parts[0];
          String permissions = parts[1];
          //String description = (parts.length >= 3 ? parts[2] : "");

          // android.permission.ACCESS_FINE_LOCATION or
          // android.permission.ACCESS_COARSE_LOCATION and android.permission.ACCESS_LOCATION_EXTRA_COMMANDS
          String[] distinctPermGroups = permissions.split(" or ");
          for (String group : distinctPermGroups) {
            List<String> combination = Arrays.asList(group.split(" and "));

            // Transform to Smali
            //apiCall = apiCall.replace("java.lang.String", "Ljava.lang.String;");
            apiCall = apiCall.replace(".", "/");

            result.put(apiCall, combination);
          }

          return true;
        }

        public Multimap<String, List<String>> getResult() {
          return result;
        }
      });

      // unique api calls: permissionMap.asMap.entrySet()
      for (Map.Entry<String, List<String>> apiCall : permissionMap.entries()) {
        //System.out.println(apiCall.getKey());
        //System.out.println("\t" + apiCall.getValue().toString());
      }

    } catch (IOException e) {
      LOGGER.error(e.getMessage());
    }
  }

  public Multimap<String, List<String>> getPermissionMap() {
    return permissionMap;
  }
}
