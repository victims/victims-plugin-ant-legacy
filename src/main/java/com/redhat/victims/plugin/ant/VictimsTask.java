package com.redhat.victims.plugin.ant;

/*
 * #%L
 * This file is part of victims-plugin-ant.
 * %%
 * Copyright (C) 2013 The Victims Project
 * %%
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 * #L%
 */

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Vector;
import java.util.jar.Attributes;
import java.util.jar.JarInputStream;
import java.util.jar.Manifest;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import org.apache.tools.ant.BuildException;
import org.apache.tools.ant.Task;
import org.apache.tools.ant.types.FileSet;
import org.apache.tools.ant.types.LogLevel;
import org.apache.tools.ant.types.Path;
import org.apache.tools.ant.types.Resource;
import org.apache.tools.ant.types.resources.FileProvider;
import org.apache.tools.ant.types.resources.FileResource;
import org.apache.tools.ant.util.ResourceUtils;

import com.redhat.victims.VictimsConfig;
import com.redhat.victims.VictimsException;
import com.redhat.victims.VictimsRecord;
import com.redhat.victims.VictimsResultCache;
import com.redhat.victims.VictimsScanner;
import com.redhat.victims.database.VictimsDB;
import com.redhat.victims.database.VictimsDBInterface;
import com.redhat.victims.fingerprint.Metadata;

//import org.codehaus.plexus.component.configurator.expression.ExpressionEvaluationException;

/**
 * @author kgreav
 */
public class VictimsTask extends Task {

    /*
     * Default options for Victims connectivity
     */
    private static final String METADATA_DEFAULT = "warning";
    private static final String FINGERPRINT_DEFAULT = "fatal";
    private static final String UPDATES_DEFAULT = "auto";
    private static final String USER_DEFAULT = "victims";
    private static final String PASS_DEFAULT = "victims";
    private static final String BASE_URL_DEFAULT = "http://www.victi.ms/";
    private static final String ENTRY_DEFAULT = "service/";
    private static final String METADATA = "metadata";
    private static final String FINGERPRINT = "fingerprint";
    
    protected Vector<FileSet> filesets = new Vector<FileSet>();
  //  protected File jar;
    private VictimsResultCache cache;
    private Path path;
    private String metadata = METADATA_DEFAULT;
    private String fingerprint = FINGERPRINT_DEFAULT;
    private String jdbcDriver = VictimsDB.defaultDriver();
    private String jdbcUrl = VictimsDB.defaultURL();
    private String jdbcUser = USER_DEFAULT;
    private String jdbcPass = PASS_DEFAULT;
    private String updates = UPDATES_DEFAULT;
    private String entryPoint = ENTRY_DEFAULT;
    private String baseUrl = BASE_URL_DEFAULT;
    
    /* Allowed values: warning, fatal, disabled */
    private String currentMode;



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
    public void vulnerabilityDetected(String action, Metadata meta, String cve)
            throws BuildException {
        String impVersion = Attributes.Name.IMPLEMENTATION_VERSION.toString();
        String id = Attributes.Name.IMPLEMENTATION_VENDOR_ID.toString();

        // Report finding
        String logMsg = TextUI.fmt(
                Resources.INFO_VULNERABLE_DEPENDENCY, id,
                impVersion, cve.trim());

        log(logMsg);

        // Fail if in fatal mode
        StringBuilder errMsg = new StringBuilder();
        errMsg.append(TextUI.box(TextUI.fmt(Resources.ERR_VULNERABLE_HEADING)))
                .append(TextUI.fmt(Resources.ERR_VULNERABLE_DEPENDENCY, cve));

        if (inFatalMode()) {
            throw new VictimsBuildException(errMsg.toString());
        }

    }

    /**
     * Interface into task, executed after all setXXX, createXXX methods.
     * Creates and synchronises database then checks supplied dependencies
     * against the vulnerability database.
     */
    public void execute() throws BuildException {
        int cores = Runtime.getRuntime().availableProcessors();
        ExecutorService executor = null;
        List<Future<FileStub>> jobs = null;
        
        setupConfig();
        
        try {
 
            // Create DB instance and sync
            VictimsDBInterface db = VictimsDB.db();
            if (updatesEnabled()) {
                log(TextUI.fmt(Resources.INFO_UPDATES,
                        VictimsConfig.serviceURI()));
                db.synchronize();
            }

            executor = Executors.newFixedThreadPool(cores);
            jobs = new ArrayList<Future<FileStub>>();
            
            // Find all files under supplied path
            Path sources = createUnifiedSourcePath();
            log("Scanning Files ");
            for (Resource r : sources) {
                
                // Grab the file
                FileResource fr = ResourceUtils.asFileResource(r
                        .as(FileProvider.class));
                
                FileStub fs = new FileStub(fr.getFile());
                String fsid = fs.getId();
                
                //Check the cache
                if (cache.exists(fs.getId())){
                	HashSet<String> cves = cache.get(fsid);
                	log("Cached: " + fsid, LogLevel.DEBUG.getLevel());
                	/* need to alter vulndetected for this */
                	if (! cves.isEmpty()){
                    	StringBuilder errMsg = new StringBuilder();
                    	errMsg.append(TextUI.box(TextUI.fmt(Resources.ERR_VULNERABLE_HEADING)))
                    		.append(TextUI.fmt(Resources.ERR_VULNERABLE_DEPENDENCY, cves));
                    	if (inFatalMode())
                    		throw new VictimsBuildException(errMsg.toString());
                    	else 
                    		log(errMsg.toString(), LogLevel.WARN.getLevel());
                	}
                	continue;
                }
                
                Callable<FileStub> worker = new VictimsCommand(fs.getFile());
                jobs.add(executor.submit(worker)); 
            }
            executor.shutdown();
            
            for (Future<FileStub> future : jobs){
            	try {
            		FileStub checked = future.get();
            		if (checked != null){
            			log("Finished: " + checked.getId(), LogLevel.DEBUG.getLevel());
            			cache.add(checked.getId(), null);
            		}
            	} catch (InterruptedException ie){
            		log(ie.getMessage(), LogLevel.DEBUG.getLevel());
            	} catch (ExecutionException e) {
            		//Need an exception that is not a build exception
            		log(e, LogLevel.DEBUG.getLevel());
            		Throwable cause = e.getCause();
            		if (cause instanceof VictimsBuildException){
            			VictimsBuildException vbe = (VictimsBuildException) cause;
            		//	cache.add(v, cves);
            			log(vbe.getMessage(), LogLevel.INFO.getLevel());
            			
            			//Check for fatal mode
            		}
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
            }
   /*         boolean alreadyReported = false;
            setMode(fingerprint);
                Metadata meta = getMeta(jar);
                String dependency = jar.getAbsolutePath();
                if (!dependency.endsWith(".jar")) {
                    continue;
                }
                // Create the VictimsRecord
                for (VictimsRecord vr : VictimsScanner.getRecords(dependency)) {
                    // Do the scanning
                    for (String cve : db.getVulnerabilities(vr)) {
                        // Found something? Report it!
                        vulnerabilityDetected(getMode(), meta, cve);
                    }
                }

                if (!alreadyReported && !metadata.equals("disabled")) {
                    setMode(metadata);
                    
                    HashMap<String,String> gav = new HashMap<String,String>();
                    gav.put("groupId", meta.get("groupId"));
                    gav.put("artifactId", meta.get("artifactId"));
                    gav.put("version", meta.get("version"));

                    log(gav.get("groupId") + "\n" + gav.get("artifactId") + "\n" + gav.get("version"));
                    HashSet<String> cves = db.getVulnerabilities(gav);
                    if (! cves.isEmpty()){
                    	StringBuilder errMsg = new StringBuilder();
                    	errMsg.append(TextUI.box(TextUI.fmt(Resources.ERR_VULNERABLE_HEADING)))
                    		.append(TextUI.fmt(Resources.ERR_VULNERABLE_DEPENDENCY, cves));
                    	
                    	if (inFatalMode()){
                    		throw new VictimsBuildException(errMsg.toString());
                    	} else {
                    		log(errMsg.toString());
                    	}
                    }
                }
                
            }*/
            log("No vulnerabilites found!");
  /*      } catch (FileNotFoundException fnf) {
            log("ERROR: " + fnf.getMessage());
        } catch (IOException io) {
            log("ERROR: " + io.getMessage());
 */       } catch (VictimsException ve) {
            log("ERROR: " + ve.getMessage());
            ve.printStackTrace();
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
    public static Metadata getMeta(File jar) throws FileNotFoundException,
            IOException {
        if (!jar.getAbsolutePath().endsWith(".jar"))
            return null;
        JarInputStream jis = new JarInputStream(new FileInputStream(jar));
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
        
        /* Create results cache */
        try {
			cache = new VictimsResultCache();
		} catch (VictimsException e) {
			throw new VictimsBuildException(e.getMessage());
		}
    }

    /**
     * Check if current mode of reporting is fatal
     * 
     * @return true for fatal false for warning/disabled
     */
    private boolean inFatalMode() {
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
    public void setMode(String mode) {
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
    public String getMode() {
        return currentMode;
    }

    /**
     * Setter for jar attribute.
     * 
     * @param jar
     *            a .jar archive
     */
  /*  public void setJar(final File jar) {
        this.jar = jar;
    }*/

    /**
     * Set base URL of database. Default is http://victi.ms
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
   /* public File getJar() {
        return jar;
    }*/

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
     /*   if (jar != null) {
            // we create a fileset with the source file.
            // this lets us combine our logic for handling output directories,
            // mapping etc.
            FileSet sourceJar = new FileSet();
            sourceJar.setProject(getProject());
            sourceJar.setFile(jar);
            sourceJar.setDir(jar.getParentFile());
            sources.add(sourceJar);
        }*/
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
