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
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Vector;
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
import org.apache.tools.ant.types.resources.LogOutputResource;
import org.apache.tools.ant.util.ResourceUtils;

import com.redhat.victims.VictimsConfig;
import com.redhat.victims.VictimsException;
import com.redhat.victims.VictimsResultCache;
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
	// protected File jar;
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

	public ExecutionContext ctx;
	/* Allowed values: warning, fatal, disabled */
	private String currentMode;

	public VictimsTask() {
		ctx = new ExecutionContext();
	}

	public void execute() throws BuildException {
		execute(setupConfig());
	}

	/**
	 * Interface into task, executed after all setXXX, createXXX methods.
	 * Creates and synchronises database then checks supplied dependencies
	 * against the vulnerability database.
	 */
	public void execute(ExecutionContext ctx) throws BuildException {
		VictimsResultCache cache = ctx.getCache();
		int cores = Runtime.getRuntime().availableProcessors();
		ExecutorService executor = null;
		List<Future<FileStub>> jobs = null;

		LogOutputResource log = ctx.getLog();
		setupConfig();

		try {
			// Sync database
			updateDatabase(ctx);

			// Concurrency, yay!
			executor = Executors.newFixedThreadPool(cores);
			jobs = new ArrayList<Future<FileStub>>();

			// Find all files under supplied path
			Path sources = createUnifiedSourcePath();
			log.log("Scanning Files ");
			for (Resource r : sources) {
				// Grab the file
				FileResource fr = ResourceUtils.asFileResource(r
						.as(FileProvider.class));
				FileStub fs = new FileStub(fr.getFile());
				String fsid = fs.getId();

				// Check the cache
				if (cache.exists(fs.getId())) {
					HashSet<String> cves = cache.get(fsid);
					log.log("Cached: " + fsid, LogLevel.DEBUG.getLevel());

					/* need to alter vulndetected for this */
					if (!cves.isEmpty()) {
						VulnerableDependencyException err = new VulnerableDependencyException(
								fs, Settings.FINGERPRINT, cves);
						log.log(err.getLocalizedMessage(),
								LogLevel.INFO.getLevel());
						if (err.isFatal(ctx))
							;
						throw new VictimsBuildException(err.getErrorMessage());
					}
					continue;
				}

				// Process dependencies that haven't been cached
				Callable<FileStub> worker = new VictimsCommand(ctx, fs);
				jobs.add(executor.submit(worker));
			}
			executor.shutdown();

			// Check the results
			for (Future<FileStub> future : jobs) {
				try {
					FileStub checked = future.get();
					if (checked != null) {
						log.log("Finished: " + checked.getId(),
								LogLevel.DEBUG.getLevel());
						cache.add(checked.getId(), null);
					}
				} catch (InterruptedException ie) {
					log.log(ie.getMessage(), LogLevel.DEBUG.getLevel());
				} catch (ExecutionException e) {
					// Need an exception that is not a build exception
					log(e, LogLevel.DEBUG.getLevel());
					Throwable cause = e.getCause();
					if (cause instanceof VulnerableDependencyException) {
						VulnerableDependencyException vbe 
							= (VulnerableDependencyException) cause;
						cache.add(vbe.getId(), vbe.getVulnerabilites());
						log.log(vbe.getMessage(), LogLevel.INFO.getLevel());

						// Check for fatal mode
						if (vbe.isFatal(ctx))
							throw new VictimsBuildException(
									vbe.getErrorMessage());
					} else {
						throw new VictimsBuildException(e.getCause()
								.getMessage());
					}
				}
			}
		} catch (VictimsException ve) {
			log(ve, LogLevel.DEBUG.getLevel());
			throw new VictimsBuildException(ve.getMessage());
			
		} finally {
			if (executor != null){
				executor.shutdown();
			}
		}
	}



	/**
	 * Updates the database according to the given configuration
	 * 
	 * @param ctx
	 * @throws VictimsException
	 */
	public void updateDatabase(ExecutionContext ctx) throws VictimsException {

		VictimsDBInterface db = ctx.getDatabase();
		LogOutputResource log = ctx.getLog();

		Date updated = db.lastUpdated();

		// update automatically every time
		if (ctx.updateAlways()) {
			log.log(TextUI.fmt(Resources.INFO_UPDATES, updated.toString(),
					VictimsConfig.uri()), LogLevel.INFO.getLevel());
			db.synchronize();

			// update once per day
		} else if (ctx.updateDaily()) {

			Date today = new Date();
			SimpleDateFormat cmp = new SimpleDateFormat("yyyMMdd");
			boolean updatedToday = cmp.format(today)
					.equals(cmp.format(updated));

			if (!updatedToday) {
				log.log(TextUI.fmt(Resources.INFO_UPDATES, updated.toString(),
						VictimsConfig.uri()), LogLevel.INFO.getLevel());
				db.synchronize();

			} else {
				log.log("Database last synchronized: " + updated.toString(),
						LogLevel.DEBUG.getLevel());
			}

			// updates disabled
		} else {
			log.log("Database synchronization disabled.",
					LogLevel.INFO.getLevel());
		}

	}

	/**
	 * Set up VictimsConfig key.
	 */
	public ExecutionContext setupConfig() {

		ctx.setLog(new LogOutputResource(this));
		ctx.setSettings(new Settings());

		// Only need to query using one hashing mechanism
		System.setProperty(VictimsConfig.Key.ALGORITHMS, "SHA512");

		/* Create results cache & victims DB */
		try {
			VictimsResultCache cache = new VictimsResultCache();
			ctx.setCache(cache);

			VictimsDBInterface db = VictimsDB.db();
			ctx.setDatabase(db);

			// validate
			ctx.getSettings().validate();
			ctx.getSettings().show(ctx.getLog());

		} catch (VictimsException e) {
			log(e, LogLevel.DEBUG.getLevel());
			throw new VictimsBuildException(e.getMessage());
		}

		return ctx;
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
	/*
	 * public void setJar(final File jar) { this.jar = jar; }
	 */

	/**
	 * Set base URL of database. Default is http://victi.ms
	 * 
	 * @param baseUrl
	 *            base URL of database
	 */
	public void setbaseUrl(String baseUrl) {
		System.setProperty(VictimsConfig.Key.URI, baseUrl);
		ctx.getSettings().set(VictimsConfig.Key.URI, baseUrl);
	}

	/**
	 * Set REST entry point into database. default is /service
	 * 
	 * @param entrypoint
	 *            entry point path
	 */
	public void entryPoint(String entrypoint) {
		System.setProperty(VictimsConfig.Key.ENTRY, entryPoint);
		ctx.getSettings().set(VictimsConfig.Key.URI, entryPoint);
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
			ctx.getSettings().set(Settings.METADATA, metadata);
		} else {
			throw new VictimsBuildException("Incorrect Metadata setting. "
					+ "Options include:" + "\tfatal warning disabled");
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
			ctx.getSettings().set(Settings.FINGERPRINT, fingerprint);
		} else {
			throw new VictimsBuildException("Incorrect Fingerprint setting. "
					+ "Options include:" + "\tfatal warning disabled");
		}
	}

	/**
	 * Set driver type to use
	 * 
	 * @param jdbcDriver
	 *            driver name
	 */
	public void setJdbcDriver(String jdbcDriver) {
		System.setProperty(VictimsConfig.Key.DB_DRIVER, jdbcDriver);
		ctx.getSettings().set(VictimsConfig.Key.DB_DRIVER, jdbcDriver);
	}

	/**
	 * Set database URL
	 * 
	 * @param jdbcUrl
	 *            URL to database
	 */
	public void setJdbcUrl(String jdbcUrl) {
		System.setProperty(VictimsConfig.Key.DB_URL, jdbcUrl);
		ctx.getSettings().set(VictimsConfig.Key.DB_URL, jdbcUrl);
	}

	/**
	 * Set the update mode. Options allowed are auto and offline
	 * 
	 * @param updates
	 *            update mode
	 */
	public void setUpdates(String updates) {
		if (updates.equalsIgnoreCase("auto")
				|| updates.equalsIgnoreCase("offline")
				|| updates.equalsIgnoreCase("daily")) {
			ctx.getSettings().set(Settings.UPDATE_DATABASE, updates);
		}
	}

	public void setJdbcUser(String jdbcUser) {
		System.setProperty(VictimsConfig.Key.DB_USER, jdbcUser);
		ctx.getSettings().set(VictimsConfig.Key.DB_USER, jdbcUser);
	}

	public void setJdbcPass(String jdbcPass) {
		System.setProperty(VictimsConfig.Key.DB_PASS, jdbcPass);
		ctx.getSettings().set(VictimsConfig.Key.DB_PASS, "(not shown)");
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
	/*
	 * public File getJar() { return jar; }
	 */

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
		return ctx.getSettings().get(VictimsConfig.Key.URI);
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
		return ctx.getSettings().get(fingerprint);
	}

	/**
	 * Get database driver
	 * 
	 * @return driver name
	 */
	public String getJdbcDriver() {
		return ctx.getSettings().get(VictimsConfig.Key.DB_DRIVER);
	}

	/**
	 * Get database URL
	 * 
	 * @return database URL
	 */
	public String getJdbcUrl() {
		return ctx.getSettings().get(VictimsConfig.Key.DB_URL);
	}

	public String getJdbcUser() {
		return ctx.getSettings().get(VictimsConfig.Key.DB_USER);
	}

	public String getJdbcPass() {
		return ctx.getSettings().get(VictimsConfig.Key.DB_PASS);
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
		/*
		 * if (jar != null) { // we create a fileset with the source file. //
		 * this lets us combine our logic for handling output directories, //
		 * mapping etc. FileSet sourceJar = new FileSet();
		 * sourceJar.setProject(getProject()); sourceJar.setFile(jar);
		 * sourceJar.setDir(jar.getParentFile()); sources.add(sourceJar); }
		 */
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
