package main

import (
	"archive/zip"
	"encoding/csv"
	"fmt"
	"log"
	"os"
	"os/user"
	"regexp"
	"strconv"
	"time"

	"github.com/fatih/color"
	"github.com/urfave/cli/v2"
)

/* hold details on each match */
type match struct {
	fullPath       string
	version        string
	md5hash        string
	whitelist      bool
	isContainer    bool
	containerImage string
	ignore         bool
	timestamp      string
}

var files []string  /* all jars, wars, and ears */
var matches []match /* jars, wars, and ears with the vulnerable library */

func mainHandler(banner bool, path string, suppress bool, headers bool, imd5 string, ipath string, icimage string) {

	bannerString := `
░█░░░█▀█░█▀▀░█░█░█▀▀░█░█░█▀▀░█░░░█░░░░░█▀▀░█▀▀░█▀█░▀█▀░▀█▀░█▀█░█▀▀░█░░
░█░░░█░█░█░█░░▀█░▀▀█░█▀█░█▀▀░█░░░█░░░░░▀▀█░█▀▀░█░█░░█░░░█░░█░█░█▀▀░█░░
░▀▀▀░▀▀▀░▀▀▀░░░▀░▀▀▀░▀░▀░▀▀▀░▀▀▀░▀▀▀░░░▀▀▀░▀▀▀░▀░▀░░▀░░▀▀▀░▀░▀░▀▀▀░▀▀▀

- A CVE-2021-44228/CVE-2021-45046/CVE-2021-45105 Scanner
- v1.0.0
- by Osama Elnaggar

`

	if !banner && !suppress {
		fmt.Printf(bannerString)
	}

	cwd, err := os.Getwd()
	if err != nil {
		cwd = "."
	}
	if path == "." {
		path = cwd
	}

	// 0a. Check user permissions

	currUser, err := user.Current()
	if err == nil {
		if currUser.Username != "root" && !suppress {
			color.Set(color.FgHiRed)
			fmt.Println("[*] WARNING: Running as non-root user.")
			fmt.Println("             Non-readable files / dirs will be skipped")
			fmt.Println("             Container mapping will fail\n")
			color.Unset()
		}
	}

	// 1. Find all jars, uber-jars, ears and wars
	printLine("[*] Starting shallow scan ............ ", suppress)
	findArchives(path)
	color.Set(color.FgCyan)
	printLine("[DONE]\n", suppress)
	color.Unset()

	// 2. Search for log4j-core-2.X in them

	printLine("[*] Starting deep scan ............... ", suppress)
	for _, f := range files {
		b, v := checkLog4j(f)
		// 2a. Search for direct log4j-core-2.X matches
		if b {
			m := match{fullPath: f, version: v, isContainer: false, timestamp: time.Now().Format(time.RFC3339)}
			matches = append(matches, m)
			// 2b. Go through uber-jars, wars and ears
		} else {
			// check for file size first
			fi, err := os.Stat(f)
			if err != nil {
				continue
			}

			if fi.Size() > 0 {
				r, err := zip.OpenReader(f)
				if err != nil {
					continue
				}

				for _, i := range r.File {
					// fmt.Println(listZipFiles(i))
					b, v := listZipFiles(i)
					if b {
						m := match{fullPath: f, version: v, isContainer: false, timestamp: time.Now().Format(time.RFC3339)}
						matches = append(matches, m)
					}
				}
				r.Close()
			}
		}
	}
	color.Set(color.FgCyan)
	printLine("[DONE]\n", suppress)
	color.Unset()

	// 2b. Add MD5 sum details
	printLine("[*] Calculating MD5 hashes ........... ", suppress)
	for i := range matches {
		match := &matches[i]
		b, _ := checkLog4j(match.fullPath)
		// we won't have log4j-core-X files
		if b == false {
			match.md5hash = md5er(match.fullPath)
		}
	}
	color.Set(color.FgCyan)
	printLine("[DONE]\n", suppress)
	color.Unset()

	// 3. Enrich them with Docker and Kubernetes information, etc.
	// 3a. Docker with overlayfs storage driver
	printLine("[*] Performing container image lookups ", suppress)
	findDockerOverlayContainers()
	findDockerAufsContainers()
	// 3b. Containerd Runtime
	findContainerdContainers()
	color.Set(color.FgCyan)
	printLine("[DONE]\n", suppress)
	color.Unset()

	// 3c. CRIO runtime
	findCrioContainers()

	// 4. Print results
	// 4a. Get primary IP
	ip := getPrimaryIPAddr()

	// 4b. Get hostname
	hostname, _ := os.Hostname()

	// 4c. Process ignore list(s)
	printLine("[*] Processing ignore list(s) ........ ", suppress)
	if imd5 != "" {
		ignoreMatches(imd5, "md5")
	}

	if ipath != "" {
		ignoreMatches(ipath, "fullPath")
	}

	if icimage != "" {
		ignoreMatches(icimage, "containerImage")
	}
	color.Set(color.FgCyan)
	printLine("[DONE]\n", suppress)
	color.Unset()

	validMatches := 0
	for _, i := range matches {
		if !(i.ignore) {
			validMatches++
		}
	}

	// 4d. Ignore / filter our non-useful results such as snapshot directories -

	re := regexp.MustCompile(`\/var\/lib\/containerd\/io.containerd.snapshotter.v1.overlayfs\/snapshots\/`)
	for i := range matches {
		res := re.FindStringSubmatch(matches[i].fullPath)
		if len(res) > 0 {
			match := &matches[i]
			match.ignore = true
		}
	}

	re = regexp.MustCompile(`\/var\/lib\/containers\/storage\/overlay\/\S{64}\/diff\/`)
	for i := range matches {
		res := re.FindStringSubmatch(matches[i].fullPath)
		if len(res) > 0 {
			match := &matches[i]
			match.ignore = true
		}
	}

	re = regexp.MustCompile(`\/var\/lib\/docker\/aufs\/(mnt|diff)\/\S{64}\/`)
	for i := range matches {
		res := re.FindStringSubmatch(matches[i].fullPath)
		if len(res) > 0 {
			match := &matches[i]
			// no match means the container is not running / stale entries
			if match.containerImage == "" {
				match.ignore = true
			}
		}
	}

	// 4e. Write CSV output
	printLine("[*] Generating output ................ ", suppress)
	color.Set(color.FgCyan)
	printLine("[DONE]\n\n", suppress)
	color.Unset()
	color.Unset()
	if validMatches > 0 {

		if !headers {
			printCSVHeader()
		}

		w := csv.NewWriter(os.Stdout)

		for _, i := range matches {
			if !(i.ignore) {
				row := []string{ip, hostname, "", "", "", "", i.md5hash, i.timestamp, strconv.FormatBool(i.isContainer), i.containerImage, i.fullPath, i.version}
				if err := w.Write(row); err != nil {
					log.Fatalln("Error writing record to csv")
				}
			}
		}

		w.Flush()

		if err := w.Error(); err != nil {
			log.Fatal(err)
		}
	}

}

func printCSVHeader() {
	fmt.Println("IP,Hostname,AppName,Team,Ignore (Y/N),Comments,MD5Hash,Timestamp,Container,ContainerImage,FullPath,Version")
}

func main() {
	// Steps
	// 0. Read user input
	app := &cli.App{
		Version: "v1.0.0",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "path",
				Value:   ".",
				Aliases: []string{"p"},
				Usage:   "Path to search",
			},
			&cli.BoolFlag{
				Name:    "no-banner",
				Aliases: []string{"nb"},
				Usage:   "Suppress banner",
			},
			&cli.BoolFlag{
				Name:    "no-messages",
				Aliases: []string{"nm"},
				Usage:   "Suppress messages except for CSV output",
			},
			&cli.BoolFlag{
				Name:    "no-header",
				Aliases: []string{"nh"},
				Usage:   "Suppress header in CSV output",
			},
			&cli.StringFlag{
				Name:    "imd5",
				Aliases: []string{"im"},
				Usage:   "Ignore MD5 hashes. Refer to the GitHub page for expected format",
			},
			&cli.StringFlag{
				Name:    "ipath",
				Aliases: []string{"ip"},
				Usage:   "Ignore file path matches. Refer to the GitHub page for expected format",
			},
			&cli.StringFlag{
				Name:    "icimage",
				Aliases: []string{"ic"},
				Usage:   "Ignore container image matches. Refer to the GitHub page for expected format",
			},
			&cli.BoolFlag{
				Name:    "print-headers",
				Aliases: []string{"ph"},
				Usage:   "Print CSV Headers only",
			},
		},
		Name:  "Log4Shell Sentinel",
		Usage: "by Osama Elnaggar",
		Action: func(c *cli.Context) error {
			if c.Bool("print-headers") {
				printCSVHeader()
			} else {
				mainHandler(c.Bool("no-banner"), c.String("path"), c.Bool("no-messages"), c.Bool("no-header"), c.String("imd5"), c.String("ipath"), c.String("icimage"))
			}
			return nil
		},
	}

	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}

}
