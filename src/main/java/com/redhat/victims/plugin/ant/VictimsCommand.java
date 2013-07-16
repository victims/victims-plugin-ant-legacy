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
import java.util.HashMap;
import java.util.HashSet;
import java.util.concurrent.Callable;
import java.util.jar.JarInputStream;
import java.util.jar.Manifest;

import org.apache.tools.ant.types.LogLevel;

import com.redhat.victims.VictimsRecord;
import com.redhat.victims.VictimsScanner;
import com.redhat.victims.database.VictimsDBInterface;
import com.redhat.victims.fingerprint.Metadata;

public class VictimsCommand implements Callable<FileStub> {
	private FileStub jar;
	private ExecutionContext ctx;

	VictimsCommand(ExecutionContext ctx, FileStub jar) {
		this.jar = jar;
		this.ctx = ctx;
	}

	public FileStub call() throws Exception {
		System.out.println(jar.getFileName());
		assert(ctx != null);
		ctx.getLog().log("Scanning: " + jar.getFileName());
		VictimsDBInterface db = ctx.getDatabase();
		String dependency = jar.getFile().getAbsolutePath();

		// fingerprint
		if (ctx.isEnabled(Settings.FINGERPRINT)) {
			
			for (VictimsRecord vr : VictimsScanner.getRecords(dependency)) {
				HashSet<String> cves = db.getVulnerabilities(vr);
				if (!cves.isEmpty()) {
					throw new VulnerableDependencyException(jar,
							Settings.FINGERPRINT, cves);
				}
			}
		}

		// metadata
		if (ctx.isEnabled(Settings.METADATA)){
			Metadata meta = getMeta(jar.getFile());
			// Create the VictimsRecord

            HashMap<String,String> gav = new HashMap<String,String>();
            gav.put("groupId", meta.get("groupId"));
            gav.put("artifactId", meta.get("artifactId"));
            gav.put("version", meta.get("version"));
            HashSet<String> cves = db.getVulnerabilities(gav);
            if (! cves.isEmpty()){
              throw new VulnerableDependencyException(jar, Settings.METADATA, cves);
			}
		}
		return jar;
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

}
