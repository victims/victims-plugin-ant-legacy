package com.redhat.victims.plugin.ant;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Date;
import java.util.jar.JarInputStream;
import java.util.jar.Manifest;

import org.apache.commons.codec.binary.Hex;
import org.apache.commons.codec.digest.MessageDigestAlgorithms;

import com.redhat.victims.VictimsException;
import com.redhat.victims.fingerprint.Metadata;

/**
 * Holds dependency metadata for caching
 * @author kurt
 */
public class FileStub {
	private Date cached;
	private String filename;
	private String id;
	private File file;
	private Metadata meta;

	/**
	 * Holds metadata for file, if unreachable file we can't
	 * cache it.
	 * @param file file to cache
	 * @throws VictimsException if can't be hashed
	 */
	public FileStub(File file) throws VictimsException {
		try {
			filename = file.getName();
			id = hashFile(file, filename);
			this.file = file;
			meta = getMeta(file);
		} catch (IOException io) {
			filename = null;
			id = null;
		}
		cached = new Date();
	}

	/**
	 * Hash the file to get a "unique" key for caching
	 * @param file file to hash
	 * @param name canonical file name
	 * @return name + md5 hash of file
	 * @throws VictimsException
	 */
	private static String hashFile(File file, String name)
			throws VictimsException {
		try {
			InputStream fis = new FileInputStream(file);
			byte[] buffer = new byte[1024];

			MessageDigest mda = MessageDigest
					.getInstance(MessageDigestAlgorithms.MD5);
			int numRead;
			do {
				numRead = fis.read(buffer);
				if (numRead > 0) {
					mda.update(buffer, 0, numRead);
				}
			} while (numRead != -1);

			fis.close();
			return name + Hex.encodeHexString(mda.digest());

		} catch (NoSuchAlgorithmException e) {
			throw new VictimsException(String.format("Could not hash file: %s",
					name), e);
		} catch (IOException io) {
			throw new VictimsException(String.format("Could not open file: %s",
					name), io);
		}
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
    
    public String getArtifactId(){
    	return meta.get("artifactId");
    }
    
    public String getVersion(){
    	return meta.get("version");
    }
	/**
	 * @return File for this Stub
	 */
	public File getFile(){
		return file;
	}
	/**
	 * @return unique file identifier
	 */
	public String getId(){
		return id;
	}
	/**
	 * @return Canonical file name
	 */
	public String getFileName() {
		return filename;
	}

	/**
	 * @return Date when file was cached
	 */
	public Date getCachedDate() {
		return cached;
	}

	public String toString() {
		return String.format("id: %s, file: %s, created on: %s", id, filename,
				cached.toString());
	}
}
