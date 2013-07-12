package com.redhat.victims.plugin.ant;

import java.io.File;
import java.util.HashSet;

import com.redhat.victims.VictimsException;

public class VulnerableDependencyException extends VictimsException {

	private String infoMessage;
	private String errorMessage;
	private String artifact;
	private String action;
	private HashSet<String> cves;
	private boolean fatalMode;

	public VulnerableDependencyException(FileStub fs, String action,
			HashSet<String> cves, boolean fatal) {
		super(String.format("CVE: %s, File: %s", cves, fs.getId()));

		this.action = action;
		this.infoMessage = TextUI.fmt(Resources.INFO_VULNERABLE_DEPENDENCY,
				fs.getArtifactId(), fs.getVersion(), cves.toString());

		StringBuilder errMsg = new StringBuilder();
		errMsg.append(TextUI.box(TextUI.fmt(Resources.ERR_VULNERABLE_HEADING)))
				.append(TextUI.fmt(Resources.ERR_VULNERABLE_DEPENDENCY, cves));

		this.errorMessage = errMsg.toString();
		this.cves = cves;
		this.artifact = fs.getId();
	}

	public String getId() {
		return this.artifact;
	}

	public String getErrorMessage() {
		return this.errorMessage;
	}

	public String getLogMessage() {
		return this.infoMessage;
	}

	public HashSet<String> getVulnerabilites() {
		return this.cves;
	}
}
