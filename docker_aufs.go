package main

import (
	"bufio"
	"context"

	// "github.com/docker/docker/api/types"
	"os"
	"path/filepath"
	"regexp"

	"github.com/docker/docker/client"
)

// *findDockerAufsContainers* will map Docker containers using the *aufs* storage driver to the corresponding
// image
// https://stackoverflow.com/questions/47400479/find-to-which-container-or-image-a-docker-aufs-diff-folder-belongs-to
// it will match entries such as: /var/lib/docker/aufs/diff/b3e8f4a721f46384260c55daf33ae52e1026bf130a10bbe3150485a2de32d573/...
func findDockerAufsContainers() {
	re := regexp.MustCompile(`\/var\/lib\/docker\/aufs\/diff\/(?P<Hash>\S{64})\/`)
	re_path := regexp.MustCompile(`\/var\/lib\/docker\/image\/aufs\/layerdb\/mounts\/(?P<Hash>\S{64})\/mount-id`)
	files, err := filepath.Glob("/var/lib/docker/image/aufs/layerdb/mounts/*/mount-id")
	if err != nil {
		return
	}

	// 1. iterate over the files
	for _, file := range files {
		f, err := os.Open(file)
		if err == nil {

			defer f.Close()
			scanner := bufio.NewScanner(f)

			// 2. for each file, open and read its contents (I'm not sure if I have to remove a newline or not)
			for scanner.Scan() {
				// 3. for each file, iterate over the matches
				for i := range matches {
					res := re.FindStringSubmatch(matches[i].fullPath)
					if len(res) > 0 {
						match := &matches[i]
						match.isContainer = true
						hash := res[1]
						fileTxt := scanner.Text()
						if fileTxt == hash {
							res_path := re_path.FindStringSubmatch(file)
							if len(res_path) > 0 {
								// 4. get container image
								cli, err := client.NewClientWithOpts(client.FromEnv)
								if err == nil {
									container, err := cli.ContainerInspect(context.Background(), res_path[1])
									if err == nil {
										match.containerImage = container.Config.Image
									}
								}
							}
						}
					}
				}
			}
		}
	}
}
