package com.redhat.victims;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.Vector;
import com.redhat.victims.database.VictimsDB;
import com.redhat.victims.database.VictimsDBInterface;
import com.redhat.victims.fingerprint.Metadata;
import com.redhat.victims.VictimsConfig;
import java.util.jar.JarInputStream;
import java.util.jar.Manifest;
import java.util.jar.Attributes;
import org.apache.tools.ant.Task;
import org.apache.tools.ant.BuildException;
import org.apache.tools.ant.types.Path;
import org.apache.tools.ant.types.Resource;
import org.apache.tools.ant.types.FileSet;
import org.apache.tools.ant.types.resources.FileProvider;
import org.apache.tools.ant.types.resources.FileResource;
import org.apache.tools.ant.util.ResourceUtils;

//import org.codehaus.plexus.component.configurator.expression.ExpressionEvaluationException;

/**
 * @author kgreav
 */
public class VictimsTask extends Task {

    protected File jar;

    /*
     * Default options for Victims connectivity
     */
    private static final String METADATA_DEFAULT = "warning";
    private static final String FINGERPRINT_DEFAULT = "fatal";
    private static final String UPDATES_DEFAULT = "auto";
    private static final String DRIVER_DEFAULT = "org.h2.Driver";
    private static final String JDBC_URL_DEFAULT = ".victims";
    private static final String USER_DEFAULT = "";
    private static final String PASS_DEFAULT = "";
    private static final String BASE_URL_DEFAULT = "https://victi.ms";
    private static final String ENTRY_DEFAULT = "/service";

    protected Vector<FileSet> filesets = new Vector<FileSet>();
    private Path path;
    private String metadata = METADATA_DEFAULT;
    private String fingerprint = FINGERPRINT_DEFAULT;
    private String jdbcDriver = DRIVER_DEFAULT;
    private String jdbcUrl = JDBC_URL_DEFAULT;
    private String jdbcUser = USER_DEFAULT;
    private String jdbcPass = PASS_DEFAULT;
    private String updates = UPDATES_DEFAULT;
    private String entryPoint = ENTRY_DEFAULT;
    private String baseUrl = BASE_URL_DEFAULT;
    /** Allowed values: warning, fatal, disabled */
    private static String currentMode;

    private static final String METADATA = "metadata";
    private static final String FINGERPRINT = "fingerprint";

    // private String tolerance = Settings.defaults.get(Settings.TOLERANCE);

    public VictimsTask() {
    }

    /**
     * Reports vulnerable dependencies, hopefully in a nice format. Code taken
     * from enforcer plugin and probably needs updating to use some sort of
     * execution context.
     * 
     * @param action Action being performed. (fingerprint or metadata)
     * @param meta Metadata extracted from jar manifest in the form of
     * {@link com.redhat.victims.fingerprint.Metadata}
     * @param cve Relevant CVE to vulnerability
     * @throws VictimsException
     */
    private void vulnerabilityDetected(String action, Metadata meta, String cve)
            throws VictimsException {
        String impVersion = Attributes.Name.IMPLEMENTATION_VERSION.toString();
        String id = Attributes.Name.IMPLEMENTATION_VENDOR_ID.toString();

        // Report finding
        String logMsg = TextUI.fmt(Resources.INFO_VULNERABLE_DEPENDENCY, id,
                impVersion, cve.trim());

        log("!!!!!!" + action + "\n\n" + logMsg);

        // Fail if in fatal mode
        StringBuilder errMsg = new StringBuilder();
        errMsg.append(TextUI.box(TextUI.fmt(Resources.ERR_VULNERABLE_HEADING)))
                .append(TextUI.fmt(Resources.ERR_VULNERABLE_DEPENDENCY, cve));

        if (inFatalMode()) {
            throw new VictimsException(errMsg.toString());
        }

    }

    /**
     * Interface into task, executed after all setXXX, createXXX methods.
     * Creates and synchronises database then checks supplied dependencies
     * against the vulnerability database.
     */
    public void execute() throws BuildException {
        try {
            setupConfig();
            // Create DB instance and sync
            VictimsDBInterface db = VictimsDB.db();

            if (updatesEnabled()) {
                log(TextUI.fmt(Resources.INFO_UPDATES,
                        VictimsConfig.serviceURI()));
                db.synchronize();
            }
            // Find all files under supplied path
            Path sources = createUnifiedSourcePath();
            log("Scanning Files ");
            for (Resource r : sources) {
                boolean alreadyReported = false;
                setMode(fingerprint);
                // Grab the file
                FileResource fr = ResourceUtils.asFileResource(r
                        .as(FileProvider.class));
                File jar = fr.getFile();
                Metadata meta = getMetadata(jar);
                String dependency = jar.getAbsolutePath();
                if (!dependency.endsWith(".jar")) {
                    continue;
                }
                // Create the VictimsRecord
                for (VictimsRecord vr : VictimsScanner.getRecords(dependency)) {
                    // Do the scanning
                    for (String cve : db.getVulnerabilities(vr)) {
                        // Found something? Report it!
                        vulnerabilityDetected(FINGERPRINT, meta, cve);
                    }
                }

                if (!alreadyReported && !metadata.equals("disabled")) {
                    setMode(metadata);
                    /*
                     * for (String cve : db.getVulnerabilities(gav)) {
                     * vulnerabilityDetected(ctx, cve); }
                     */
                }
            }

        } catch (FileNotFoundException fnf) {
            log("ERROR: \n" + fnf.getMessage());
        } catch (IOException io) {
            log("ERROR: \n" + io.getMessage());
        } catch (VictimsException ve) {
            log("ERROR: \n" + ve.getMessage());
        }

    }

    /**
     * Creates metadata from a given jar file.
     * 
     * @param jar
     *            file containing a manifest
     * @return Metadata containing extracted information from manifest file.
     * @throws FileNotFoundException
     * @throws IOException
     */
    private static Metadata getMetadata(File jar) throws FileNotFoundException,
            IOException {
        if (jar.getAbsolutePath().endsWith(".jar"))
            return null;
        JarInputStream jis;
        jis = new JarInputStream(new FileInputStream(jar));
        Manifest mf = jis.getManifest();
        jis.close();
        if (mf != null) {
            return Metadata.fromManifest(mf);
        }
        return null;
    }

    /**
     * Set up VictimsConfig key.
     */
    public void setupConfig() {
        if (baseUrl != null) {
            System.setProperty(VictimsConfig.Key.URI, baseUrl);
        }
        if (entryPoint != null) {
            System.setProperty(VictimsConfig.Key.ENTRY, entryPoint);
        }
        if (jdbcDriver != null) {
            System.setProperty(VictimsConfig.Key.DB_DRIVER, jdbcDriver);
        }
        if (jdbcUrl != null) {
            System.setProperty(VictimsConfig.Key.DB_URL, jdbcUrl);
        }
        if (jdbcUser != null) {
            System.setProperty(VictimsConfig.Key.DB_USER, jdbcUser);
        }
        if (jdbcPass != null) {
            System.setProperty(VictimsConfig.Key.DB_PASS, jdbcPass);
        }
    }

    /**
     * Check if current mode of reporting is fatal
     * 
     * @return true for fatal false for warning/disabled
     */
    private static boolean inFatalMode() {
        if (getMode().equalsIgnoreCase("fatal")) {
            return true;
        } else {
            return false;
        }

    }

    /**
     * Set the reporting mode
     * 
     * @param mode
     *            value of warning, fatal, or disabled
     */
    private static void setMode(String mode) {
        if (mode.equalsIgnoreCase("warning") || mode.equalsIgnoreCase("fatal")
                || mode.equalsIgnoreCase("disabled")) {
            currentMode = mode;
        }
    }

    /**
     * Get the current mode
     * 
     * @return Current reporting mode
     */
    private static String getMode() {
        return currentMode;
    }

    /**
     * Setter for jar attribute.
     * 
     * @param jar
     *            a .jar archive
     */
    public void setJar(final File jar) {
        this.jar = jar;
    }

    /**
     * Set base URL of database. Default is https://victi.ms
     * 
     * @param baseUrl
     *            base URL of database
     */
    public void setbaseUrl(String baseUrl) {
        this.baseUrl = baseUrl;
    }

    /**
     * Set REST entry point into database. default is /service
     * 
     * @param entrypoint
     *            entry point path
     */
    public void entryPoint(String entrypoint) {
        this.entryPoint = entrypoint;
    }

    /**
     * Set metadata mode. Options allowed are warning, fatal, disabled.
     * 
     * @param metadata
     *            metadata severity mode
     */
    public void setMetadata(String metadata) {
        if (metadata.equalsIgnoreCase("warning")
                || metadata.equalsIgnoreCase("fatal")
                || metadata.equalsIgnoreCase("disabled")) {
            this.metadata = metadata;
        } else {
            throw new BuildException("Incorrect Metadata setting. "
                    + "Options include: \n" + "\t\tfatal warning disabled");
        }
    }

    /**
     * Set fingerprint mode. Options allowed are warning, fatal, disabled.
     * 
     * @param fingerprint
     *            fingerprinting severity mode
     */
    public void setFingerprint(String fingerprint) {
        if (fingerprint.equalsIgnoreCase("warning")
                || fingerprint.equalsIgnoreCase("fatal")
                || fingerprint.equalsIgnoreCase("disabled")) {
            this.fingerprint = fingerprint;
        } else {
            throw new BuildException("Incorrect Fingerprint setting. "
                    + "Options include: \n" + "\t\tfatal warning disabled");
        }
    }

    /**
     * Set driver type to use
     * 
     * @param jdbcDriver
     *            driver name
     */
    public void setJdbcDriver(String jdbcDriver) {
        this.jdbcDriver = jdbcDriver;
    }

    /**
     * Set database URL
     * 
     * @param jdbcUrl
     *            URL to database
     */
    public void setJdbcUrl(String jdbcUrl) {
        this.jdbcUrl = jdbcUrl;
    }

    /**
     * Set the update mode. Options allowed are auto and offline
     * 
     * @param updates
     *            update mode
     */
    public void setUpdates(String updates) {
        if (updates.equalsIgnoreCase("auto")
                || updates.equalsIgnoreCase("offline")) {
            this.updates = updates;
        } else {
            this.updates = UPDATES_DEFAULT;
        }
    }

    /**
     * Setter for nested path attribute
     * 
     * @param path
     *            built from filesets.
     */
    public void setPath(final Path path) {
        this.path = path;
    }

    /**
     * Initialise the path variable. Called from ant after initialisation.
     * 
     * @return A path to .jar files
     */
    public Path createPath() {
        if (this.path == null) {
            path = new Path(getProject());
        }
        return path.createPath();
    }

    /**
     * Getter for jar file.
     * 
     * @return a single .jar file
     */
    public File getJar() {
        return jar;
    }

    /**
     * Getter for path
     * 
     * @return a path to .jar files
     */
    public Path getPath() {
        return path;
    }

    /**
     * Get baseUrl
     * 
     * @return database URL
     */
    public String getbaseUrl() {
        return baseUrl;
    }

    /**
     * Get metadata mode
     * 
     * @return metadata mode
     */
    public String getMetadata() {
        return metadata;
    }

    /**
     * Get fingerprint mode
     * 
     * @return fingerprint mode
     */
    public String getFingerprint() {
        return fingerprint;
    }

    /**
     * Get database driver
     * 
     * @return driver name
     */
    public String getjdbcDiver() {
        return jdbcDriver;
    }

    /**
     * Get database URL
     * 
     * @return database URL
     */
    public String getjdbcUrl() {
        return jdbcUrl;
    }

    /**
     * Get update mode
     * 
     * @return update mode
     */
    public String getUpdates() {
        return updates;
    }

    /**
     * Updates enabled check
     * 
     * @return true if updates are enabled
     */
    public boolean updatesEnabled() {
        String val = getUpdates();
        return val != null && val.equalsIgnoreCase("auto");
    }

    /**
     * clone our filesets vector, and patch in the jar attribute as a new
     * fileset, if is defined
     * 
     * @return a vector of FileSet instances
     */
    protected Vector<FileSet> createUnifiedSources() {
        @SuppressWarnings("unchecked")
        Vector<FileSet> sources = (Vector<FileSet>) filesets.clone();
        if (jar != null) {
            // we create a fileset with the source file.
            // this lets us combine our logic for handling output directories,
            // mapping etc.
            FileSet sourceJar = new FileSet();
            sourceJar.setProject(getProject());
            sourceJar.setFile(jar);
            sourceJar.setDir(jar.getParentFile());
            sources.add(sourceJar);
        }
        return sources;
    }

    /**
     * clone our path and add all explicitly specified FileSets as well, patch
     * in the jar attribute as a new fileset if it is defined.
     * 
     * @return a path that contains all files to list
     */
    protected Path createUnifiedSourcePath() {
        Path p = path == null ? new Path(getProject()) : (Path) path.clone();
        for (FileSet fileSet : createUnifiedSources()) {
            p.add(fileSet);
        }
        return p;
    }
}
