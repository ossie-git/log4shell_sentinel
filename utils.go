package main

import (
	"archive/zip"
	"crypto/md5"
	"encoding/csv"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	mapset "github.com/deckarep/golang-set"
)

func printLine(line string, suppress bool) {
	if !suppress {
		fmt.Print(line)
	}
}

// *getPrimaryIPAddr* returns the primary interface on the machine
func getPrimaryIPAddr() string {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		log.Fatal(err)
	}

	defer conn.Close()
	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return localAddr.IP.String()
}

// *md5er* takes a file path and returns the corresponding MD5 checksum
func md5er(fullPath string) string {
	file, err := os.Open(fullPath)

	if err != nil {
		return ""
	}

	defer file.Close()

	hash := md5.New()
	_, err = io.Copy(hash, file)

	if err != nil {
		return ""
	}

	return hex.EncodeToString(hash.Sum(nil))
}

// *listZipFiles* takes a zip file and lists it contents
func listZipFiles(file *zip.File) (bool, string) {
	f, err := file.Open()
	if err != nil {
		msg := "Failed to open zip %s for reading: %s"
		fmt.Println(msg)
		return false, ""
	}
	defer f.Close()

	return checkLog4j(file.Name)
}

// *findArchives* searches the path passed to it for .jar, .war and .ear files
// It does not look into them to see if they have log4-core-2.x
// ignore entries such as /var/lib/docker/overlay2/9e570f0cec8dcff5662a940f205600b541f82bd7d5d9c9bea8975ecb072506f4/diff/app/spring-boot-application.jar because
// they do not reflect running containers
func findArchives(path string) {
	filepath.Walk(path, func(path string, info os.FileInfo, err error) error {
		// suppress errors / ignore files we can't read
		if err == nil {
			if !info.IsDir() && (filepath.Ext(path) == ".jar" || filepath.Ext(path) == ".war" || filepath.Ext(path) == ".ear") {
				reOverlay := regexp.MustCompile(`\/var\/lib\/docker\/overlay2?\/\S{64}\/diff\/`)
				resOverlay := reOverlay.FindStringSubmatch(path)
				if len(resOverlay) == 0 {
					files = append(files, path)
				}
			}
		}
		return nil
	})
}

// *checkLog4j* takes a file and checks to see if it is one of the affected versions or not
// if it finds a match, it returns true + the version
// *NOTE* anything below 7 is considered vulnerable to one of the high / critical CVEs as
// mentioned here - https://logging.apache.org/log4j/2.x/security.html
// CVE-2021-45105, CVE-2021-45046, CVE-2021-44228
func checkLog4j(path string) (bool, string) {
	// taken from: https://mvnrepository.com/artifact/org.apache.logging.log4j/log4j-core
	log4jSlice := []interface{}{
		"log4j-core-2.16.0.jar",
		"log4j-core-2.15.0.jar",
		"log4j-core-2.14.1.jar",
		"log4j-core-2.14.0.jar",
		"log4j-core-2.13.3.jar",
		"log4j-core-2.13.2.jar",
		"log4j-core-2.13.1.jar",
		"log4j-core-2.13.0.jar",
		"log4j-core-2.12.2.jar",
		"log4j-core-2.12.1.jar",
		"log4j-core-2.12.0.jar",
		"log4j-core-2.11.2.jar",
		"log4j-core-2.11.1.jar",
		"log4j-core-2.11.0.jar",
		"log4j-core-2.10.0.jar",
		"log4j-core-2.9.1.jar",
		"log4j-core-2.9.0.jar",
		"log4j-core-2.8.2.jar",
		"log4j-core-2.8.1.jar",
		"log4j-core-2.8.jar",
		"log4j-core-2.7.jar",
		"log4j-core-2.6.2.jar",
		"log4j-core-2.6.1.jar",
		"log4j-core-2.6.jar",
		"log4j-core-2.5.jar",
		"log4j-core-2.4.1.jar",
		"log4j-core-2.4.jar",
		"log4j-core-2.3.jar",
		"log4j-core-2.2.jar",
		"log4j-core-2.1.jar",
		"log4j-core-2.0.2.jar",
		"log4j-core-2.0.1.jar",
		"log4j-core-2.0.jar",
		"log4j-core-2.0-rc2.jar",
		"log4j-core-2.0-rc1.jar",
		"log4j-core-2.0-beta9.jar",
		"log4j-core-2.0-beta8.jar",
		"log4j-core-2.0-beta7.jar",
		"log4j-core-2.0-beta6.jar",
		"log4j-core-2.0-beta5.jar",
		"log4j-core-2.0-beta4.jar",
		"log4j-core-2.0-beta3.jar",
		"log4j-core-2.0-beta2.jar",
		"log4j-core-2.0-beta1.jar",
		"log4j-core-2.0-alpha2.jar",
		"log4j-core-2.0-alpha1.jar"}
	log4jSet := mapset.NewSetFromSlice(log4jSlice)
	_, file := filepath.Split(path)

	if log4jSet.Contains(file) {
		return true, file
	}

	return false, file
}

// *ingoreRow* is a generic structure to read our ignore lists, regardless of if they are
// for MD5 hashes, paths or container images
type ignoreRow struct {
	key     string
	appName string
	reason  string
}

// *ignoreMatches* allows us to ignore / suppress results with the corresponding MD5 hashes,
// file paths or container image names
func ignoreMatches(file string, ignoreKey string) {

	// intercept malformed CSV files
	defer func() {
		if err := recover(); err != nil {
			fmt.Println("\nERORR: Malformed *ignore file*. Exiting")
			os.Exit(1)
		}
	}()

	csvFile, err := os.Open(file)
	if err != nil {
		log.Fatal("Error opening ignore list", file)
	}
	defer csvFile.Close()

	csvLines, err := csv.NewReader(csvFile).ReadAll()
	if err != nil {
		log.Fatal(err)
	}
	// the first row may just be the headers. Won't skip it as even if
	// it is a header, it won't match any MD5 sum so it is harmless
	for _, line := range csvLines {
		row := ignoreRow{
			key:     line[0],
			appName: line[1],
			reason:  line[2],
		}

		for i := range matches {
			match := &matches[i]
			if ignoreKey == "md5" {
				if match.md5hash == row.key {
					match.ignore = true
				}
			} else if ignoreKey == "fullPath" {
				if match.fullPath == row.key {
					match.ignore = true
				}
			} else if ignoreKey == "containerImage" {
				if match.containerImage == row.key {
					match.ignore = true
				}
			}
		}
	}
}

// *checkBinary* checks to see if a binary is in the
// PATH or not
func checkBinary(cmd string) bool {
	_, err := exec.LookPath(cmd)
	if err != nil {
		return false
	}
	return true
}

// *crictlCheckContainer* takes an image name and checks to see
// if the corresponding container is running or not
// crictl ps does not show image tags - https://github.com/kubernetes-sigs/cri-tools/issues/454
// but critcl images does. So we will do a best effort and check both
// this isn't definitive
func crictlCheckContainer(name string) bool {
	re := regexp.MustCompile(`(?P<image>[^:]+):(?P<tag>\S+)`)
	res := re.FindStringSubmatch(name)
	if len(res) > 0 {
		image := res[1]
		tag := res[2]

		// check *crictl ps* output first using image name
		outp, _ := exec.Command("crictl", "ps").Output()
		if strings.Contains(fmt.Sprint(string(outp)), image) {

			// check *crictl images* output using image name + tag
			outi, _ := exec.Command("crictl", "images").Output()
			// build dynamic regex
			whitespace := `\s+`
			regDynamicString := fmt.Sprintf("%s%s%s", image, whitespace, tag)
			rei := regexp.MustCompile(regDynamicString)
			resi := rei.FindStringSubmatch(string(outi))
			if len(resi) > 0 {
				return true
			}
		}
	}
	return false
}
