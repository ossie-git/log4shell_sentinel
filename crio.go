package main

import (
	"io/ioutil"
	"os"
	"os/user"
	"path/filepath"
	"strings"

	"github.com/tidwall/gjson"
)

// *findCrioContainers* will check to see if any of our matches are CRI-O containers and
// will append image-related metadata. If an image is not found, it will add the pod name
// instead
// the default client does not support extracting metadata as mentioned here:
// https://github.com/cri-o/cri-o/issues/3567 so I resorted to parsing the on-disk files
func findCrioContainers() {
	var containerImage string
	currUser, _ := user.Current()
	path := "/var/lib/containers/storage/overlay-containers/"
	filepath.Walk(path, func(path string, info os.FileInfo, err error) error {
		// suppress errors / ignore files we can't read
		if err == nil {
			if !info.IsDir() && (filepath.Base(path) == "config.json") {
				jsonFile, err := os.Open(path)
				if err == nil {
					byteValue, _ := ioutil.ReadAll(jsonFile)
					rootPath := gjson.GetBytes(byteValue, "root.path")
					imageName := gjson.GetBytes(byteValue, `annotations.io\.kubernetes\.cri-o\.ImageName`)
					podName := gjson.GetBytes(byteValue, `annotations.io\.kubernetes\.pod\.name`)
					// NOTE containers run directly from kubelet do not have a corresponding ImageName. As backup,
					// I'll use the pod name if there is no ImageName
					if imageName.String() == "" {
						containerImage = podName.String()
					} else {
						containerImage = imageName.String()
					}
					for i := range matches {
						match := &matches[i]
						if strings.Contains(match.fullPath, rootPath.String()) {
							match.containerImage = containerImage
							match.isContainer = true
							// check if it is running or not. Requires root + crictl
							// we ignore any containers that are not running
							if err == nil {
								if checkBinary("crictl") && currUser.Username == "root" {
									if crictlCheckContainer(match.containerImage) == false {
										match.ignore = true
									}
								}
							}
						}
					}
				}
				defer jsonFile.Close()
			}
		}
		return nil
	})
}
