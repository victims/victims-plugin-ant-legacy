package com.redhat.victims.plugin.ant;

import java.io.File;
import java.util.concurrent.Callable;

public class VictimsCommand implements Callable<FileStub> {
	private File jar;
	
	VictimsCommand(File jar){
		this.jar = jar;
	}
	public FileStub call() throws Exception {
		
		return null;
	}

}
