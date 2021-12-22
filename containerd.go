package main

import (
	"github.com/tidwall/gjson"
	"io/ioutil"
	"os"
	"regexp"
)

// *findContainerdContainers* cycles through our matches and checks to see goes through out matches and checks
// to see if any are containerd containers (overlayfs). If so, it extracts the image name
// and adds it to the record
// this will match entries such as this:
// /run/containerd/io.containerd.runtime.v2.task/k8s.io/dc2c9c214809f506283c917244cd126a9b056ac7274322d12b59c9196d95dd9b/rootfs/app/spring-boot-application.jar
// I originally used the client https://pkg.go.dev/github.com/containerd/containerd but then decided to just parse on the on-disk file to remove the extra dependencies
// To extract the image name:
// # cat /run/containerd/io.containerd.runtime.v2.task/k8s.io/dc2c9c214809f506283c917244cd126a9b056ac7274322d12b59c9196d95dd9b/config.json | jq '.annotations."io.kubernetes.cri.image-name"'
// "ghcr.io/christophetd/log4shell-vulnerable-app:latest"
func findContainerdContainers() {
	re := regexp.MustCompile(`\/run\/containerd\/io.containerd.runtime.v2.task\/k8s.io\/(?P<Hash>\S{64})\/`)
	for i := range matches {
		res := re.FindStringSubmatch(matches[i].fullPath)
		if len(res) > 0 {
			match := &matches[i]
			match.isContainer = true
			hash := res[1]

			jsonFile, err := os.Open("/run/containerd/io.containerd.runtime.v2.task/k8s.io/" + hash + "/config.json")
			if err == nil {
				byteValue, _ := ioutil.ReadAll(jsonFile)
				imageName := gjson.GetBytes(byteValue, `annotations.io\.kubernetes\.cri\.image-name`)
				if imageName.String() != "" {
					match.containerImage = imageName.String()
				}
			}
			defer jsonFile.Close()
		}
	}
}
