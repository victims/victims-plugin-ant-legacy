package com.redhat.victims;

import static org.junit.Assert.*;

import com.redhat.victims.VictimsException;
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
    
    @Test
    public void test() {
        
        vt.init();
        Path path = new Path(project, "/home/kurt/ant/apache-ant-1.9.0/lib/*");
        Path path2 = path.createPath();
        vt.setPath(path2);
        vt.execute();
  /*      for (Resource r : sources) {
            FileResource fr = ResourceUtils.asFileResource(r
                    .as(FileProvider.class));
            System.out.println(fr.getFile().getAbsolutePath());
            assert fr.getFile().getAbsolutePath()
                    .equals("/home/kurt/ant/apache-ant-1.9.0/lib");
        }*/
        
    }
    
    @Test(expected=VictimsException.class)
    public void testVulnerabilityDetected() throws VictimsException {
        String action = "fingerprint";
        String cve    = "CVE-1111-1111";
        Metadata meta = new Metadata();
        vt.setMode("fatal");
        vt.vulnerabilityDetected(action, meta, cve);
    }

}
