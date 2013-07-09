package com.redhat.victims.plugin.ant;

import static org.junit.Assert.*;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.HashMap;

import com.redhat.victims.VictimsException;

import org.apache.tools.ant.BuildException;
import org.apache.tools.ant.Project;
import org.apache.tools.ant.types.Path;
import org.apache.tools.ant.types.Resource;
import org.apache.tools.ant.types.resources.FileProvider;
import org.apache.tools.ant.types.resources.FileResource;
import org.apache.tools.ant.util.ResourceUtils;
import org.junit.Rule;
import org.junit.Test;

import com.redhat.victims.fingerprint.Metadata;

public class VictimsTaskTest {

    VictimsTask vt = new VictimsTask();
    Project project = new Project();
    
    /**
     * Lazy way to run the program
     */
    @Test
    public void test() {
        
        vt.init();
        Path path = new Path(project, "/home/kurt/ant/apache-ant-1.9.0/lib/*");
        Path path2 = path.createPath();
        vt.setPath(path2);
        vt.execute();        
    }
    
    /*
     * Checks correct exception is thrown
     */
    @Test(expected=BuildException.class)
    public void testVulnerabilityDetected() throws VictimsException {
        String action = "fingerprint";
        String cve    = "CVE-1111-1111";
        Metadata meta = new Metadata();
        vt.setMode("fatal");
        vt.vulnerabilityDetected(action, meta, cve);
    }
    
    @Test
    public void testExecute(){
    	vt.init();
    	vt.setProject(project);
        Path path = new Path(project, "");
        Path path2 = path.createPath();
        vt.setPath(path2);
        /* assert default settings exist */
        assertTrue(vt.getPath() != null);
        assertTrue(!vt.getbaseUrl().equals(""));
        assertTrue(!vt.getProject().equals(""));
        assertTrue(vt.getUpdates().equalsIgnoreCase("auto")
        			|| vt.getUpdates().equalsIgnoreCase("offline"));
        vt.execute();
        
    }
    
    /**
     * Needs jar with proper manifest info!
     */
    @Test
    public void testMetadata(){
    	vt.init();
    	vt.setMode("fatal");
    	File jar = new File("testdata","spring-2.5.6.jar");
    	assertTrue(jar.canRead());
    	try {
    		Metadata meta = VictimsTask.getMeta(jar);
    		HashMap<String,String> gav = new HashMap<String,String>();
    		if (meta.containsKey("Manifest-Version"))
    			gav.put("groupId", meta.get("Manifest-Version"));
    		if (meta.containsKey("Implementation-Version"))
    			gav.put("artifactId", meta.get("Implementation-Version"));
    		if (meta.containsKey("Implementation-Title"))
    			gav.put("version", meta.get("Implementation-Title"));
    		
            assertTrue(gav.get("groupId").equals("1.0"));
            assertTrue(gav.get("artifactId").equals("2.5.6"));
            assertTrue(gav.get("version").equals("Spring Framework"));
    	} catch (FileNotFoundException fn){
    		
    	} catch (IOException ie){
    		
    	}
    }

}
