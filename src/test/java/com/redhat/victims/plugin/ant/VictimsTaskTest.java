package com.redhat.victims.plugin.ant;

import static org.junit.Assert.*;

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

}
