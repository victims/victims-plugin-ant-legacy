package com.redhat.victims;

import java.io.File;
import java.util.Vector;
import com.redhat.victims.fingerprint.Fingerprint;
//import com.redhat.victims.fingerprint.*;
import com.redhat.victims.synchronizer.*;
/*
import com.redhat.victims.commands.Command;
import com.redhat.victims.commands.ExecutionContext;
import com.redhat.victims.commands.FingerprintCommand;
import com.redhat.victims.commands.MetadataCommand;
*/
import com.redhat.victims.database.Database;
import com.redhat.victims.VictimsScanner;
import org.apache.tools.ant.Task;
import org.apache.tools.ant.BuildException;
import org.apache.tools.ant.types.Path;
import org.apache.tools.ant.types.Resource;
import org.apache.tools.ant.types.FileSet;
import org.apache.tools.ant.types.resources.FileProvider;
import org.apache.tools.ant.types.resources.FileResource;
import org.apache.tools.ant.util.ResourceUtils;
import org.apache.tools.ant.DefaultLogger;

//import org.codehaus.plexus.component.configurator.expression.ExpressionEvaluationException;


/**
 * @author kurt with credit to apache for code taken from
 *         org.apache.tools.ant.taskdefs.SignJar for.
 */
public class VictimsTask extends Task {

	protected File jar;

	protected Vector<FileSet> filesets = new Vector<FileSet>();
	private Path path;
	private String url;
	private String metadata;
	private String fingerprint;
	private String dbdriver;
	private String dburl;
	private String updates;
	private String tolerance;

	//private Command[] commands = { new MetadataCommand(),
	//		new FingerprintCommand() };

	public VictimsTask() {
	}

	/**
	 * Interface into task, executed after all setXXX, createXXX methods.
	 */
	public void execute() throws BuildException {
	//	String message = getProject().getProperty("ant.project.name");
	//	log("Project: " + message);
		
		try {
            Settings setup = new Settings();
            setup.set(Settings.URL, url);
            setup.set(Settings.METADATA, metadata);
            setup.set(Settings.FINGERPRINT, fingerprint);
            setup.set(Settings.UPDATE_DATABASE, updates);
            setup.set(Settings.DATABASE_DRIVER, dbdriver);
            setup.set(Settings.DATABASE_URL, dburl);
            setup.set(Settings.TOLERANCE, tolerance);
            setup.validate();
            
            // Create database instance
            Database db = new Database(dbdriver, dburl);
            
            if(setup.updatesEnabled()){
            	Synchronizer sync = new Synchronizer(setup.get(Settings.URL));
            	sync.synchronizeDatabase(db);
            }
            
    		Path sources = createUnifiedSourcePath();
    		log("\n");
    		System.out.println("Resources: ");
    		for(Resource r : sources){
    			System.out.println(r.getName());
    			
    		}
    		VictimsScanner.scan(sources.toString(), System.out);
/*   		for (Resource r : sources) {
    			FileResource fr = ResourceUtils.asFileResource(r
    					.as(FileProvider.class));
    			File file = fr.getFile();

    			log("\t" + file.getAbsolutePath());
    		}
*/
            
		} catch (Exception e){
			System.out.println("exception");
		}


//		log("Included files:\n");
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
