package com.redhat.victims;

import static org.junit.Assert.*;

import org.apache.tools.ant.Project;
import org.apache.tools.ant.types.Path;
import org.apache.tools.ant.types.Resource;
import org.apache.tools.ant.types.resources.FileProvider;
import org.apache.tools.ant.types.resources.FileResource;
import org.apache.tools.ant.util.ResourceUtils;
import org.junit.Test;

public class VictimsTaskTest {

	@Test
	public void test() {
		VictimsTask vt = new VictimsTask();
		Project project = new Project();
		Path path = new Path(project, "/this/path");
		vt.setPath(path);
		Path sources = vt.createUnifiedSourcePath();
		vt.execute();
		for (Resource r : sources){
			FileResource fr = ResourceUtils.asFileResource(r
					.as(FileProvider.class));
			System.out.println(fr.getFile().getAbsolutePath());
			assert fr.getFile().getAbsolutePath().equals("/this/path");
		}
	}

}
