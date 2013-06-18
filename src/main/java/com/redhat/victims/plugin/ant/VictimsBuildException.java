package com.redhat.victims.plugin.ant;

import org.apache.tools.ant.BuildException;

public class VictimsBuildException extends BuildException {

	private static final long serialVersionUID = -3411399027684620634L;
	VictimsBuildException(){
		super();
	}
	VictimsBuildException(String err){
		super(err);
	}
}
