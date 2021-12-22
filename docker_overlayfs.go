package main

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/client"
)

// *findDockerOverContainers* goes through Docker containers backed by the
// overlayfs storage driver and maps the corresponding container image
// this will match entries such as this: /var/lib/docker/overlay2/3839945137d898a38d7c91666d06ca99324d2858667439288cf6978d2829be5d/...
// https://docs.docker.com/storage/storagedriver/overlayfs-driver/
// https://pkg.go.dev/github.com/docker/docker@v20.10.12+incompatible/api/types#GraphDriverData
// NOTE:
// - you'll typically have two entries for a single container:
// 1. the merged layer
// 2. the diff layer
// for example:
// /var/lib/docker/overlay2/192768f471818601094bf4edd96d14bfc0e2b178a04a2efd00b2231ad4e46b33/merged/app/spring-boot-application.jar
// /var/lib/docker/overlay2/9e570f0cec8dcff5662a940f205600b541f82bd7d5d9c9bea8975ecb072506f4/diff/app/spring-boot-application.jar
// we'll match just the *merged* layer as this indicates a running container
func findDockerOverlayContainers() {
	re := regexp.MustCompile(`\/var\/lib\/docker\/overlay2?\/(?P<Hash>\S{64})\/merged\/`)
	cli, err := client.NewClientWithOpts(client.FromEnv)
	if err == nil {
		for i := range matches {
			res := re.FindStringSubmatch(matches[i].fullPath)
			if len(res) > 0 {
				match := &matches[i]
				match.isContainer = true
				hash := res[1]
				containers, err := cli.ContainerList(context.Background(), types.ContainerListOptions{})
				if err == nil {
					for _, container := range containers {
						res, _ := cli.ContainerInspect(context.Background(), container.ID)
						// fmt.Sprint is ugly but does the job
						if strings.Contains(fmt.Sprint(res.GraphDriver), hash) {
							match.containerImage = container.Image
						}
					}
				}
			}
		}
	}
}
