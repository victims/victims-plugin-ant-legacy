package com.redhat.victims.plugin.ant;

import static org.junit.Assert.*;

import java.io.File;
import java.io.FileNotFoundException;
import java.util.HashMap;

import com.redhat.victims.VictimsException;

import org.apache.tools.ant.Project;
import org.apache.tools.ant.types.Path;
import org.junit.Test;

import com.redhat.victims.fingerprint.Metadata;

public class VictimsTaskTest {

	VictimsTask vt = new VictimsTask();
	Project project = new Project();

	@Test
	public void testFileStub()
	{
		File jar = new File("testdata", "spring-2.5.6.jar");
		File fakejar = new File("testdata", "fake-jar_test-1.1.5.jar");
		try {
			FileStub fs = new FileStub(jar);
			assertTrue(fs.getId().contains("spring-2.5.6.jar"));
			assertTrue(fs.getFile().equals(jar));
			assertTrue(fs.getArtifactId().equals("spring"));
			assertTrue(fs.getTitle().equals("Spring Framework"));
			
			/* Test artifact id creation */
			FileStub fj = new FileStub(fakejar);
			assertTrue(fj.getArtifactId().equals("fake-jar_test"));
			assertTrue(fj.getVersion().equals("1.1.5"));
			
		} catch (VictimsException e) {
			fail("ERROR: " + e.getMessage());
		}
	}

    @Test
    public void testNoManifest() throws Exception {
        // Check we handle .jars without manifests correctly.
        File jar = new File("testdata", "no_manifest.jar");
        try {
            FileStub fs= new FileStub(jar);
            assertTrue(fs.getVersion() == null);
        } catch (VictimsException e){
            fail(e.toString());
        }
    }

    @Test
    public void testWrongFileType() throws Exception {
        // Check we safely ignore files that are not .jar compatible formats.
        File jar = new File("testdata", "wrong_file.test");
        try {
            FileStub fs = new FileStub(jar);

        } catch(VictimsException e){
            e.printStackTrace();
            fail(e.toString());
        }
    }


	/**
	 * Checks correct exception is thrown
	 */
	/*@Test(expected = BuildException.class)
	public void testVulnerabilityDetected() throws VictimsException {
		String action = "fingerprint";
		String cve = "CVE-1111-1111";
		Metadata meta = new Metadata();
		// vt.vulnerabilityDetected(action, meta, cve);
	}*/

	/**
	 * Test correct defaults
	 */
	@Test
	public void testInit() {
		vt.init();
		vt.setProject(project);
		Path path = new Path(project, "");
		Path path2 = path.createPath();
		vt.setPath(path2);
		/* assert default settings exist */
		assertTrue(vt.getPath() != null);
		assertTrue(!vt.getbaseUrl().equals(""));
		assertTrue(vt.getProject() != null);
		String updates = vt.getUpdates();
		assertTrue(updates.equalsIgnoreCase("auto")
				|| updates.equalsIgnoreCase("offline")
				|| updates.equalsIgnoreCase("daily"));
		vt.setUpdates("auto");
		assertTrue(vt.updatesEnabled());
	}

	/**
	 * Tests retrieval of Jar manifest info
	 * 
	 * @throws VictimsException
	 *             if test data unavailable
	 */
	@Test
	public void testMetadata() throws VictimsException {
		vt.init();
		File jar = new File("testdata", "spring-2.5.6.jar");
		if (!jar.canRead()) {
			throw new VictimsException(
					"Test data unavailable: spring-2.5.6.jar");
		}
		try {
			Metadata meta = FileStub.getMeta(jar);
			HashMap<String, String> gav = new HashMap<String, String>();
			//fix naming
			if (meta.containsKey("Manifest-Version"))
				gav.put("groupId", meta.get("Manifest-Version"));
			if (meta.containsKey("Implementation-Version"))
				gav.put("artifactId", meta.get("Implementation-Version"));
			if (meta.containsKey("Implementation-Title"))
				gav.put("version", meta.get("Implementation-Title"));

			assertTrue(gav.get("groupId").equals("1.0"));
			assertTrue(gav.get("artifactId").equals("2.5.6"));
			assertTrue(gav.get("version").equals("Spring Framework"));
		} catch (FileNotFoundException fn) {
			//silently catch
		}
	}
	
/*	@Test(expected=VulnerableDependencyException.class)
	public void testVictimsCommand(){
		ExecutionContext ctx = new ExecutionContext();
		ctx.setDatabase(VictimsDB.db());
	} Needs to be in seperate class	*/

}
