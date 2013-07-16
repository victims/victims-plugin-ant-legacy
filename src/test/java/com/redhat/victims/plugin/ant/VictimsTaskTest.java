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
import org.junit.Test;

import com.redhat.victims.fingerprint.Metadata;

public class VictimsTaskTest {

	VictimsTask vt = new VictimsTask();
	Project project = new Project();

	public void testScan() {

	}

	/**
	 * Lazy way to run the program
	 */
	@Test
	public void test() {

		vt.init();
		Path path = new Path(project, "/home/kurt/ant/apache-ant-1.9.0/lib/*");
		Path path2 = path.createPath();
		vt.setPath(path2);
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
		System.out.println(vt.getbaseUrl());
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
			Metadata meta = VictimsCommand.getMeta(jar);
			HashMap<String, String> gav = new HashMap<String, String>();
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

		} catch (IOException ie) {

		}
	}

}
