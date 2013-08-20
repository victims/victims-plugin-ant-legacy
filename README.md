# victims-plugin-ant [![Build Status](https://travis-ci.org/victims/victims-plugin-ant.png)](https://travis-ci.org/victims/victims-plugin-ant)

## About

This Ant Task provides the functionality to scan a Java projects dependencies against a database of publicly 
known vulnerabilities. The canonical version of the database is hosted at https://victi.ms and is maintained by
Red Hat security teams.

## Getting Started

A sample Ant project is provided in sample/
The sample project requires Apache Ant & Apache Ivy, found at the following:
```
  ant.apache.org        -- Ant
  ant.apache.org/ivy    -- Ivy
```
To run:
```sh
  cd sample/
  ant
```

If successful the build should fail with a vulnerable dependency in the spring library.

## Sample build.xml
```xml
  <?xml version="1.0" encoding="ISO-8859-1"?>
      <project name="ProjectName" basedir="." default="scan">
          <!-- 
            This defines the task utilising the victims-plugin-ant jar.
            Make sure the victims-plugin-ant.jar library is available in the classpath
          -->
          <target name="define" description="Define the task">
              <taskdef name="victims" classname="com.redhat.victims.plugin.ant.VictimsTask">
                  <classpath>
                      <fileset dir="lib" includes="**/*.jar"/>
                  </classpath>
              </taskdef>
          </target>
          
          <!--
            This target executes the victims-plugin-ant task. Path is the only
            required parameter. For other possible parameters see below.
           -->
          <target name="scan" depends="define" description="Run the victims scan">
              <victims>
                  <path>
                      <fileset dir="lib" includes="**/*.jar"/>
                  </path>
              </victims>
          </target>
      </project>
```
## Configuration options reference

The following options can be specified as child elements of ```<victims>```

### baseUrl

The URL of the victims web service to used to synchronize the local database.

default: "https://victi.ms"

### entryPoint

The entrypoint of the victims webservice to synchronize against

default: "/service"

### metadata

The severity of exception to be thrown when a dependency is encountered that matches the known vulnerable database based on metadata. Fatal indicates the build should fail, warning indicates a warning should be issued but the build should proceed.

allowed : warning, fatal, disabled
default : warning

### fingerprint

The severity of exception to be thrown when a dependency is encountered that matches the known vulnerable database based on a fingerprint. Fatal indicates the build should fail, warning indicates a warning should be issued but the build should proceed.

allowed : warning, fatal, disabled
default : fatal

### updates

Allows the configuration of the synchronization mechanism. In automatic mode new entries in the victims database are pulled from the victims-web instance during each build. In daily mode new entries are pulled from the victims-web instance only once per day. The synchronization mechanism may be disabled and processed manually for closed build environments.

allowed : auto, offline TODO: daily
default : auto

### jdbcDriver

The jdbc driver to use for the local victims database. By default victims uses an embedded H2 database.

default : org.h2.Driver

### jdbcUrl

The jdbc connection URL to for the local victims database.

default : .victims (embedded h2 instance).

### jdbcUser

The username to use for the jdbc connection.

default : "victims"

### jdbcPass

The password to use for the jdbc connection.

default : "victims"
