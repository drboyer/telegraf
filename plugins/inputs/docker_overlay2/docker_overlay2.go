package docker_overlay2

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/filters"
	"github.com/influxdata/telegraf"
	"github.com/influxdata/telegraf/filter"
	"github.com/influxdata/telegraf/internal"
	"github.com/influxdata/telegraf/internal/docker"
	tlsint "github.com/influxdata/telegraf/internal/tls"
	"github.com/influxdata/telegraf/plugins/inputs"
)

// DockerOverlay2 object
type DockerOverlay2 struct {
	Endpoint string

	Timeout        internal.Duration
	TagEnvironment []string `toml:"tag_env"`
	LabelInclude   []string `toml:"docker_label_include"`
	LabelExclude   []string `toml:"docker_label_exclude"`

	ContainerInclude []string `toml:"container_name_include"`
	ContainerExclude []string `toml:"container_name_exclude"`

	ContainerStateInclude []string `toml:"container_state_include"`
	ContainerStateExclude []string `toml:"container_state_exclude"`

	IncludeVolumes bool `toml:"include_volumes"`

	tlsint.ClientConfig

	newEnvClient func() (Client, error)
	newClient    func(string, *tls.Config) (Client, error)

	client          Client
	httpClient      *http.Client
	engineHost      string
	serverVersion   string
	filtersCreated  bool
	labelFilter     filter.Filter
	containerFilter filter.Filter
	stateFilter     filter.Filter
}

const (
	defaultEndpoint = "unix:///var/run/docker.sock"
)

var (
	containerStates = []string{"created", "restarting", "running", "removing", "paused", "exited", "dead"}
	now             = time.Now
)

var sampleConfig = `
  ## Docker Endpoint
  ##   To use TCP, set endpoint = "tcp://[ip]:[port]"
  ##   To use environment variables (ie, docker-machine), set endpoint = "ENV"
  endpoint = "unix:///var/run/docker.sock"

  ## Containers to include and exclude. Globs accepted.
  ## Note that an empty array for both will include all containers
  container_name_include = []
  container_name_exclude = []

  ## Container states to include and exclude. Globs accepted.
  ## When empty only containers in the "running" state will be captured.
  ## example: container_state_include = ["created", "restarting", "running", "removing", "paused", "exited", "dead"]
  ## example: container_state_exclude = ["created", "restarting", "running", "removing", "paused", "exited", "dead"]
  # container_state_include = []
  # container_state_exclude = []

  ## Timeout for docker list, info, and stats commands
  timeout = "5s"

  ## Which environment variables should we use as a tag
  ##tag_env = ["JAVA_HOME", "HEAP_SIZE"]

  ## docker labels to include and exclude as tags.  Globs accepted.
  ## Note that an empty array for both will include all labels as tags
  docker_label_include = []
  docker_label_exclude = []

  ## Optional TLS Config
  # tls_ca = "/etc/telegraf/ca.pem"
  # tls_cert = "/etc/telegraf/cert.pem"
  # tls_key = "/etc/telegraf/key.pem"
  ## Use TLS but skip chain & host verification
  # insecure_skip_verify = false

  ## Whether to measure the size of volumes mounted to containers as well
  include_volumes = true
`

// SampleConfig returns the default DockerOverlay2 TOML configuration
func (d *DockerOverlay2) SampleConfig() string { return sampleConfig }

// Short description of the metrics returned
func (d *DockerOverlay2) Description() string {
	return "Metrics about docker container sizes"
}

// Gather metrics!
func (d *DockerOverlay2) Gather(acc telegraf.Accumulator) error {
	if d.client == nil {
		c, err := d.getNewClient()
		if err != nil {
			return err
		}
		d.client = c
	}

	// Create label filters if not already created
	if !d.filtersCreated {
		err := d.createLabelFilters()
		if err != nil {
			return err
		}
		err = d.createContainerFilters()
		if err != nil {
			return err
		}
		err = d.createContainerStateFilters()
		if err != nil {
			return err
		}
		d.filtersCreated = true
	}

	filterArgs := filters.NewArgs()
	for _, state := range containerStates {
		if d.stateFilter.Match(state) {
			filterArgs.Add("status", state)
		}
	}

	// All container states were excluded
	if filterArgs.Len() == 0 {
		return nil
	}

	// List containers
	opts := types.ContainerListOptions{
		Filters: filterArgs,
	}
	ctx, cancel := context.WithTimeout(context.Background(), d.Timeout.Duration)
	defer cancel()

	containers, err := d.client.ContainerList(ctx, opts)
	if err == context.DeadlineExceeded {
		return errors.New("timeout retrieving container list")
	}
	if err != nil {
		return err
	}

	// Get container data
	var wg sync.WaitGroup
	wg.Add(len(containers))
	for _, container := range containers {
		go func(c types.Container) {
			defer wg.Done()
			if err := d.gatherContainer(c, acc); err != nil {
				acc.AddError(err)
			}
		}(container)
	}
	wg.Wait()

	return nil
}

func (d *DockerOverlay2) gatherContainer(
	container types.Container,
	acc telegraf.Accumulator) error {

	// Parse container name
	var cname string
	for _, name := range container.Names {
		trimmedName := strings.TrimPrefix(name, "/")
		match := d.containerFilter.Match(trimmedName)
		if match {
			cname = trimmedName
			break
		}
	}

	if cname == "" {
		return nil
	}

	imageName, imageVersion := docker.ParseImage(container.Image)

	tags := map[string]string{
		"engine_host":       d.engineHost,
		"server_version":    d.serverVersion,
		"container_name":    cname,
		"container_image":   imageName,
		"container_version": imageVersion,
	}

	ctx, cancel := context.WithTimeout(context.Background(), d.Timeout.Duration)
	defer cancel()

	insp, err := d.client.ContainerInspect(ctx, container.ID)
	if err == context.DeadlineExceeded {
		return errors.New("timeout inspecting container")
	}
	if err != nil {
		return fmt.Errorf("error inspecting docker container: %v", err)
	}

	// TODO: set time to something else deterministic?
	tm := time.Now()

	// Add whitelisted environment variables to tags
	// TODO: we still need this, right?
	if len(d.TagEnvironment) > 0 {
		for _, envvar := range insp.Config.Env {
			for _, configvar := range d.TagEnvironment {
				dockEnv := strings.SplitN(envvar, "=", 2)
				//check for presence of tag in whitelist
				if len(dockEnv) == 2 && len(strings.TrimSpace(dockEnv[1])) != 0 && configvar == dockEnv[0] {
					tags[dockEnv[0]] = dockEnv[1]
				}
			}
		}
	}

	// TODO: Don't just magically pull from the map? See memstats in parseContainerStats()
	mergedDir := insp.GraphDriver.Data["MergedDir"]

	size_fields := map[string]interface{}{
		"container_root_fs_size": container.SizeRootFs,
		"container_merged_size":  d.pathSizeWalk(mergedDir),
	}

	acc.AddFields("docker_overlay2", size_fields, tags, tm)

	if d.IncludeVolumes {
		var wg sync.WaitGroup
		wg.Add(len(insp.Mounts))
		for _, mount := range insp.Mounts {
			go func(mp types.MountPoint) {
				defer wg.Done()
				d.gatherVolumeMounts(mp, tags, acc)
			}(mount)
		}
		wg.Wait()
	}

	return nil
}

func (d *DockerOverlay2) gatherVolumeMounts(mp types.MountPoint, tags map[string]string, acc telegraf.Accumulator) error {
	if mp.Type == "volume" {
		volTm := time.Now()
		// volumeTags := tags
		tags["volume_name"] = mp.Name
		tags["volume_source"] = mp.Source
		tags["volume_dest"] = mp.Destination
		tags["volume_driver"] = mp.Driver

		fields := map[string]interface{}{
			"size": d.pathSizeWalk(mp.Source),
		}

		acc.AddFields("docker_overlay2_container_volume", fields, tags, volTm)
	}

	return nil
}

// TODO: I feel like this is unoptimized
func (d *DockerOverlay2) calcSizeOfPath(currPath string) int64 {
	var size int64

	dir, err := os.Open(currPath)
	if err != nil {
		fmt.Println(err) // TODO: changeme?
		return size
	}
	defer dir.Close()

	files, err := dir.Readdir(-1)
	if err != nil {
		fmt.Println(err) // TODO: changeme?
		return size
	}

	for _, file := range files {
		if file.IsDir() {
			size += d.calcSizeOfPath(fmt.Sprintf("%s/%s", currPath, file.Name()))
		} else {
			size += file.Size()
		}
	}

	return size
}

// TODO: how to properly handle errors here
func (d *DockerOverlay2) pathSizeWalk(path string) int64 {
	var pathSize int64
	err := filepath.Walk(path, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			fmt.Printf("Couldn't access path %q: %v\n", path, err) // a warning?
		}
		if !info.IsDir() {
			pathSize = pathSize + info.Size()
		}
		return nil
	})
	if err != nil {
		fmt.Printf("error walking %v\n", err) // should "return"/throw this error. Maybe just don't handle it?
	}

	return pathSize
}

func (d *DockerOverlay2) createContainerFilters() error {
	filter, err := filter.NewIncludeExcludeFilter(d.ContainerInclude, d.ContainerExclude)
	if err != nil {
		return err
	}
	d.containerFilter = filter
	return nil
}

func (d *DockerOverlay2) createLabelFilters() error {
	filter, err := filter.NewIncludeExcludeFilter(d.LabelInclude, d.LabelExclude)
	if err != nil {
		return err
	}
	d.labelFilter = filter
	return nil
}

func (d *DockerOverlay2) createContainerStateFilters() error {
	if len(d.ContainerStateInclude) == 0 && len(d.ContainerStateExclude) == 0 {
		d.ContainerStateInclude = []string{"running"}
	}
	filter, err := filter.NewIncludeExcludeFilter(d.ContainerStateInclude, d.ContainerStateExclude)
	if err != nil {
		return err
	}
	d.stateFilter = filter
	return nil
}

func (d *DockerOverlay2) getNewClient() (Client, error) {
	if d.Endpoint == "ENV" {
		return d.newEnvClient()
	}

	tlsConfig, err := d.ClientConfig.TLSConfig()
	if err != nil {
		return nil, err
	}

	return d.newClient(d.Endpoint, tlsConfig)
}

func init() {
	inputs.Add("docker_overlay2", func() telegraf.Input {
		return &DockerOverlay2{
			Timeout:        internal.Duration{Duration: time.Second * 5},
			Endpoint:       defaultEndpoint,
			newEnvClient:   NewEnvClient,
			newClient:      NewClient,
			filtersCreated: false,
		}
	})
}
