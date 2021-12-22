# Log4Shell Sentinel - A Smart CVE-2021-44228 Scanner

## Introduction

While there have some excellent tools released to help organizations scan their environments for applications vulnerable to the critical [Log4J / CVE-2021-44228]( https://nvd.nist.gov/vuln/detail/CVE-2021-44228 ) vulnerability, I felt that:

* none of the tools I ran into were made for analysts to track a given finding throughout the remediation process. **Log4Shell Sentinel** outputs its findings to CSV format in the expectation that an analyst will then slice and dice findings in Excel, add some findings to an ignore list and re-run the scan, compare scans, add data to scan results, etc.
* file-based scanners leave a lot of work for analysts to do, especially in containerized environments

So **Log4Shell Sentinel** was born. Log4Shell Sentinel is a file-based scanner with some unique features. It isn't meant to replace all the other available tools but can compliment them.

## Features

Log4Shell Sentinel is a file-based scanner. It searches for Java-based applications by scanning a target system for artifacts of the following file formats:

| File Type | Details |
|-----------------|-----------|
|Simple jar|This is the case where the log4j-core file is not embedded.|
|Fat / Uber jar|An **uber jar** is a jar that contains both your classes / package and all your application's dependencies (libraries, resources and metadata files) within a single jar file. This is the most commonly used deployment option.|
|WAR|A **war** (Web Application Archive) file is a file that contains your JSP, HTML and JavaScript code in addition to your libraries and other resources. This format is less commonly used.|
|EAR|An **ear** (Enterprise Application Archive) is another format that was more commonly used with Jakarta EE for deployments.|

and searches for instances of vulnerable **log4j-core** jars. It then:

* calculates a MD5 hash of the artifact. This allows an analyst to identify the same application running on different machines / containers and treat them as a single finding
* for files determined to belong to a container such as: `/var/lib/docker/overlay2/192768f471818601094bf4edd96d14bfc0e2b178a04a2efd00b2231ad4e46b33/merged/app/spring-boot-application.jar`, it does the heavy lifting of mapping the file to the corresponding image. For example, it would translate the above to the following image: `ghcr.io/christophetd/log4shell-vulnerable-app:latest`. As the various container runtimes store this mapping in different ways, this can save an analyst hours of frustration. This also allows an analyst to treat a number of containers running a single application as a single finding.
* it removes useless matches such as matches corresponding to containers that are currently not running including cached images. This allows an analyst to focus on what is important and again saves the analyst hours of needless work
* it allows an analyst to ignore matches based on:
  - MD5 hash
  - file path
  - container image

  This allows the analyst to remove applications they know are not vulnerable or which correspond to CLI-based applications that do not pose a threat. For example, if an instance of Logstash is detected, an analyst can choose to ignore it if they do not run the tool or simply run it as from the CLI occasionally.

* it is optimized to work with your configuration management tools such as Ansible, giving you the ability to quickly scan your environment in minutes

### Metadata Enrichment

For details on the metadata enrichment added by Log4Shell Sentinel, refer to the my blog [post](https://osamaelnaggar.com/blog/introducing_log4shell_sentinel/).

## Installation

The easiest way is to simply download the pre-compiled binary.

### Building From Source

Again, this is straight-forward. However, you will likely want to build a statically compiled version to get around any GLIBC-related variations in your environment. The tool uses the following modules which use CGO by default:

* `os/user`
* `net`

To build a statically compiled version that uses the Go-versions of these libraries, simply clone the repo and then run:

~~~
$ CGO_ENABLED=0 go build -ldflags="-s -w"
$ ldd log4shell_sentinel
        not a dynamic executable
~~~

## Usage

~~~
$ ./log4shell_sentinel -h
NAME:
   Log4Shell Sentinel - by Osama Elnaggar

USAGE:
   log4shell_sentinel [global options] command [command options] [arguments...]

VERSION:
   v1.0.0

COMMANDS:
   help, h  Shows a list of commands or help for one command

GLOBAL OPTIONS:
   --path value, -p value       Path to search (default: ".")
   --no-banner, --nb            Suppress banner (default: false)
   --no-messages, --nm          Suppress messages except for CSV output (default: false)
   --no-header, --nh            Suppress header in CSV output (default: false)
   --imd5 value, --im value     Ignore MD5 hashes. Refer to the GitHub page for expected format
   --ipath value, --ip value    Ignore file path matches. Refer to the GitHub page for expected format
   --icimage value, --ic value  Ignore container image matches. Refer to the GitHub page for expected format
   --print-headers, --ph        Print CSV Headers only (default: false)
   --help, -h                   show help (default: false)
   --version, -v                print the version (default: false)
~~~

Out of the box, a scan will simply scan the current directory. For example:

~~~
$ ./log4shell_sentinel

░█░░░█▀█░█▀▀░█░█░█▀▀░█░█░█▀▀░█░░░█░░░░░█▀▀░█▀▀░█▀█░▀█▀░▀█▀░█▀█░█▀▀░█░░
░█░░░█░█░█░█░░▀█░▀▀█░█▀█░█▀▀░█░░░█░░░░░▀▀█░█▀▀░█░█░░█░░░█░░█░█░█▀▀░█░░
░▀▀▀░▀▀▀░▀▀▀░░░▀░▀▀▀░▀░▀░▀▀▀░▀▀▀░▀▀▀░░░▀▀▀░▀▀▀░▀░▀░░▀░░▀▀▀░▀░▀░▀▀▀░▀▀▀

- A CVE-2021-44228/CVE-2021-45046/CVE-2021-45105 Scanner
- v1.0.0
- by Osama Elnaggar

[*] WARNING: Running as non-root user.
             Non-readable files / dirs will be skipped
             Container mapping will fail

[*] Starting shallow scan ............ [DONE]
[*] Starting deep scan ............... [DONE]
[*] Calculating MD5 hashes ........... [DONE]
[*] Performing container image lookups [DONE]
[*] Processing ignore list(s) ........ [DONE]
[*] Generating output ................ [DONE]

IP,Hostname,AppName,Team,Ignore (Y/N),Comments,MD5Hash,Timestamp,Container,ContainerImage,FullPath,Version
192.168.121.121,server3,,,,,4e615cd580758b70c49ade1f79103328,2021-12-21T07:38:09Z,true,ghcr.io/christophetd/log4shell-vulnerable-app:latest,/run/containerd/io.containerd.runtime.v2.task/k8s.io/dc2c9c214809f506283c917244cd126a9b056ac7274322d12b59c9196d95dd9b/rootfs/app/spring-boot-application.jar,log4j-core-2.14.1.jar
~~~

You'll immediately get a **WARNING** if you run it as a non-root user as it requires `root` permissions:

* if you plan on scanning your entire filesystem (recommended)
* if you plan on enriching performing container -> image lookups (access to the Docker daemon, config files, etc. is required)

It will still work without `root` privileges but may not give you the best results.

### Understanding Findings

A sample finding looks like this:

~~~
IP,Hostname,AppName,Team,Ignore (Y/N),Comments,MD5Hash,Timestamp,Container,ContainerImage,FullPath,Version
192.168.121.121,server3,,,,,4e615cd580758b70c49ade1f79103328,2021-12-21T07:38:09Z,true,ghcr.io/christophetd/log4shell-vulnerable-app:latest,/run/containerd/io.containerd.runtime.v2.task/k8s.io/dc2c9c214809f506283c917244cd126a9b056ac7274322d12b59c9196d95dd9b/rootfs/app/spring-boot-application.jar,log4j-core-2.14.1.jar
~~~

Some fields are intentionally left empty and left for the analyst to fill in in Excel, etc. A short description of each field is shown below:

|Field|Example|Description|
|------|------|------|
|IP|192.168.121.121|If the instance has multiple IPs, the primary IP is added|
|Hostname|server3|Hostname|
|AppName||This is left to the user to complete after the scan is completed|
|Team||This is left to the user to complete after the scan is completed|
|Ignore (Y/N)||This is left to the user to complete after the scan is completed|
|Comment||This is left to the user to complete after the scan is completed|
|MD5Hash|4e615cd580758b70c49ade1f79103328|A unique fingerprint of our application|
|Timestamp|2021-12-21T07:38:09Z|A timestamp when the scan was performed. This is useful if you want to aggregate multiple scans of the same host|
|Container|true|True = this is a container|
|ContainerImage|ghcr.io/christophetd/log4shell-vulnerable-app:latest|If a container was detected, this is the corresponding image|
|FullPath|/run/containerd/io.containerd.<br>runtime.v2.task/k8s.io/.../spring-boot-application.jar|The full path of the finding. In this example, the vulnerable JAR file is part of a fat / uber jar|
|Version|log4j-core-2.14.1.jar|The lo4j-core version detected|

### Options

The tool comes with the following options:

|Option|Details|
|------|------|
|`--path value, -p value`|This specifies what paths to search. By default, it searches the current directory. **IMPORTANT** It is recommended that you set this to `/` to cover your entire filesystem|
|`--no-banner, --nb`|This suppresses the banner|
|`--no-messages, --nm`|This suppresses messages such a progress-related messages|
|`--no-header, --nh`|This suppresses the CSV output's header. This is recommended when running it across multiple servers|
|`--imd5 value, --im value`|Ignore MD5 hashes. More on this in the **Ignore Lists** section|
|`--ipath value, --ip value`|Ignore file path matches.  More on this in the **Ignore Lists** section|
|`--icimage value, --ic value`|Ignore container image matches. More on this in the **Ignore Lists** section|
|`--print-headers, --ph`|Print CSV Headers only. When you run Log4Shell Sentinel on multiple servers and aggregate the results, you would typically disable header output. This command outputs the header only so you can add it to your Excel sheet|

### Container Mapping -> Image Support

One of Log4Shell Sentinel's unique features not found in any other tool is the ability to translate jars found in file system scans such as:

`/var/lib/docker/overlay2/192768f471818601094bf4edd96d14bfc0e2b178a04a2efd00b2231ad4e46b33/merged/app/spring-boot-application.jar`

to the corresponding container image (the above translates to `ghcr.io/christophetd/log4shell-vulnerable-app:latest` for example). As the various container runtimes store this mapping in different ways, this can save an analyst hours of frustration. This also allows an analyst to treat a number of containers running a single application as a single finding. The solution currently supports the following lookups:

* Docker (with overlay2 storage driver)
* Docker (with aufs storage driver)
* CRI-O
* containerd

### Ignore Lists

The number of applications identified may initially be overwhelming or you may want to focus on a given subset of identified applications such as those exposed to external users first. Or you may want to focus on a given compliance scope. To support this, the application supports specifying a list. Log4Shell currently supports 3 ignore lists:

* MD5 hash ignore list
* container image ignore list
* path ignore list

Instead of simple lists, it expects a CSV file as input. This encourages the analyst to document why they are ignoring a given finding. As the analyst processes the findings and identifies non-vulnerable applications using manual or automated source code analysis or DAST tools, etc.

#### MD5 Hash Ignore List

The list is a simple CSV file in the following format:

~~~
MD5Sum,AppName,Reason
~~~

The *AppName* and *Reason* columns may be empty but are there for you to keep track of why you are including or excluding specific applications.

**NOTE** As this feature uses the MD5 hash calculated for the application, this will only work for applications that are fat / uber jars, EARs or WARs.

For example, if we had the following finding:

~~~
IP,Hostname,AppName,Team,Ignore (Y/N),Comments,MD5Hash,Timestamp,Container,ContainerImage,FullPath,Version
192.168.121.121,server3,,,,,4e615cd580758b70c49ade1f79103328,2021-12-21T07:38:09Z,true,ghcr.io/christophetd/log4shell-vulnerable-app:latest,/run/containerd/io.containerd.runtime.v2.task/k8s.io/dc2c9c214809f506283c917244cd126a9b056ac7274322d12b59c9196d95dd9b/rootfs/app/spring-boot-application.jar,log4j-core-2.14.1.jar
~~~

and determined that the application _isn't vulnerable_, we can simply save the following in `hashes.csv`:

~~~csv
4e615cd580758b70c49ade1f79103328,Demo App,Not vulnerable
~~~

and then re-run it:

~~~
# ./log4shell_sentinel --im hashes.csv --path /
~~~

the above finding would be suppressed.

#### Container Mappings -> Images Ignore List

The list is a simple CSV file in the following format:

~~~
Container Image,AppName,Reason
~~~

Building on the previous example, we can tell it to ignore any finding where the container image is: `ghcr.io/christophetd/log4shell-vulnerable-app:latest` by creating a `images.csv` file such as this:

~~~
ghcr.io/christophetd/log4shell-vulnerable-app:latest,,
~~~

and then running it by:

~~~
# ./log4shell_sentinel --ic images.csv -p /
~~~

Again, our previous finding would be suppressed.

#### Path Ignore List

Again, this is a simple CSV file in the following format:

~~~
Path,AppName,Reason
~~~

Using the example above, if we create the following `paths.csv` file:

~~~csv
/run/containerd/io.containerd.runtime.v2.task/k8s.io/dc2c9c214809f506283c917244cd126a9b056ac7274322d12b59c9196d95dd9b/rootfs/app/spring-boot-application.jar,Demo App,Not vulnerable
~~~

the previous finding would be suppressed.

**WARNING** When possibly, it is better to use an MD5 hash or container image name for suppression as the path may be not be unique

## Mass Scanning Your Environment

While it is perfectly fine to run Log4Shell Sentinel on a single server, it really shines when combined with your favorite configuration management tool (Ansible, Chef, Puppet, Salt, AWS SSM, etc.) or even simple parallel SSH tools such as [parellel-ssh](https://github.com/ParallelSSH/parallel-ssh). 

This gives you numerous benefits including:

* finding duplicate instances of your applications and containers and treating these findings as a single finding at the analysis phase
* scanning your entire environment in minutes

For a full example of this in action, refer to the my blog [post](https://osamaelnaggar.com/blog/introducing_log4shell_sentinel/)

## Workflow

Refer to the **Mass Scanning Your Environment** section.

## FAQ

* I'm not seeing all vulnerable applications. Why?
  - The primary reason is probably related to either not running it as the `root` user (it requires access to where your applications might be installed) or you having specified the correct `path`. It is recommended that you run it as the `root` user and set `--path /`
* What **limitations** does it have? Some limitations include:
  - The tool can't definitively state if a given application is vulnerable or not. Instead, it will detect if an application contains a version of the library which is vulnerable
  - If the application detected is not running in a container, the tool can't detect if a given application is running or not. So even a command line tool that uses the vulnerable version will be detected
  - The tool requires SSH access and will therefore not detect issues on systems where it can't run
* The container -> image mapping isn't working. Why?
  - As of v1.0.0, the tool currently supports mapping for the following:
    * Docker (with Overlay2 storage driver)
    * Docker (with aufs storage driver)
    * CRI-O
    * containerd

    If you are using anything else, then the mapping will not work. If you are using one of the above, it may be that you are not running the tool as the `root` user or that the socket / files used are located in a non-default location.
* What vulnerabilities does it detect? 
  - While primarily aimed at detections versions of log4j that may be susceptible to CVE-2021-45105, it also flags versions that are vulnerable to CVE-2021-45046 and CVE-2021-44228.
* Does the tool work on Windows?
  - Although I haven't tested this, it should work. However, features such as container file -> image mapping are Linux-specific.
* Are there any external dependencies?
  - No. The binary is statically compiled.

## Author

Developed by: **Osama Elnaggar**

* Website: [https://osamaelnaggar.com](https://osamaelnaggar.com)
* Twitter: [https://twitter.com/securityfu](https://twitter.com/securityfu)
* LinkedIn: [ https://www.linkedin.com/in/osama-elnaggar-08230957 ]( https://www.linkedin.com/in/osama-elnaggar-08230957 )
