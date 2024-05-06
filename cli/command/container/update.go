package container

import (
	"context"
	"fmt"
	"strings"

	"github.com/docker/cli/cli"
	"github.com/docker/cli/cli/command"
	"github.com/docker/cli/cli/command/completion"
	"github.com/docker/cli/opts"
	containertypes "github.com/docker/docker/api/types/container"
	"github.com/pkg/errors"
	"github.com/docker/go-connections/nat"
	"github.com/spf13/cobra"
)

type updateOptions struct {
	blkioWeight        uint16
	cpuPeriod          int64
	cpuQuota           int64
	cpuRealtimePeriod  int64
	cpuRealtimeRuntime int64
	cpusetCpus         string
	cpusetMems         string
	cpuShares          int64
	memory             opts.MemBytes
	memoryReservation  opts.MemBytes
	memorySwap         opts.MemSwapBytes
	kernelMemory       opts.MemBytes
	restartPolicy      string
	pidsLimit          int64
	cpus               opts.NanoCPUs


	nFlag int
	addPublish 	       opts.ListOpts
	removePublish      opts.ListOpts

	containers []string
}

type Address struct {
	IP   string
	Port string
}

// NewUpdateCommand creates a new cobra.Command for `docker update`
func NewUpdateCommand(dockerCli command.Cli) *cobra.Command {
	// var options updateOptions
	options := &updateOptions{
		addPublish:           opts.NewListOpts(nil),
		removePublish:        opts.NewListOpts(nil),
	}

	cmd := &cobra.Command{
		Use:   "update [OPTIONS] CONTAINER [CONTAINER...]",
		Short: "Update configuration of one or more containers",
		Args:  cli.RequiresMinArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			options.containers = args
			options.nFlag = cmd.Flags().NFlag()
			return runUpdate(cmd.Context(), dockerCli, options)
		},
		Annotations: map[string]string{
			"aliases": "docker container update, docker update",
		},
		ValidArgsFunction: completion.ContainerNames(dockerCli, true),
	}

	flags := cmd.Flags()
	flags.Uint16Var(&options.blkioWeight, "blkio-weight", 0, `Block IO (relative weight), between 10 and 1000, or 0 to disable (default 0)`)
	flags.Int64Var(&options.cpuPeriod, "cpu-period", 0, "Limit CPU CFS (Completely Fair Scheduler) period")
	flags.Int64Var(&options.cpuQuota, "cpu-quota", 0, "Limit CPU CFS (Completely Fair Scheduler) quota")
	flags.Int64Var(&options.cpuRealtimePeriod, "cpu-rt-period", 0, "Limit the CPU real-time period in microseconds")
	flags.SetAnnotation("cpu-rt-period", "version", []string{"1.25"})
	flags.Int64Var(&options.cpuRealtimeRuntime, "cpu-rt-runtime", 0, "Limit the CPU real-time runtime in microseconds")
	flags.SetAnnotation("cpu-rt-runtime", "version", []string{"1.25"})
	flags.StringVar(&options.cpusetCpus, "cpuset-cpus", "", "CPUs in which to allow execution (0-3, 0,1)")
	flags.StringVar(&options.cpusetMems, "cpuset-mems", "", "MEMs in which to allow execution (0-3, 0,1)")
	flags.Int64VarP(&options.cpuShares, "cpu-shares", "c", 0, "CPU shares (relative weight)")
	flags.VarP(&options.memory, "memory", "m", "Memory limit")
	flags.Var(&options.memoryReservation, "memory-reservation", "Memory soft limit")
	flags.Var(&options.memorySwap, "memory-swap", `Swap limit equal to memory plus swap: -1 to enable unlimited swap`)
	flags.Var(&options.kernelMemory, "kernel-memory", "Kernel memory limit (deprecated)")
	// --kernel-memory is deprecated on API v1.42 and up, but our current annotations
	// do not support only showing on < API-version. This option is no longer supported
	// by runc, so hiding it unconditionally.
	flags.SetAnnotation("kernel-memory", "deprecated", nil)
	flags.MarkHidden("kernel-memory")

	flags.StringVar(&options.restartPolicy, "restart", "", "Restart policy to apply when a container exits")
	flags.Int64Var(&options.pidsLimit, "pids-limit", 0, `Tune container pids limit (set -1 for unlimited)`)
	flags.SetAnnotation("pids-limit", "version", []string{"1.40"})

	flags.Var(&options.cpus, "cpus", "Number of CPUs")
	flags.SetAnnotation("cpus", "version", []string{"1.29"})
	flags.VarP(&options.addPublish, "add-publish", "", "Publish a container's port(s) to the host (form of port:port)")
	flags.VarP(&options.removePublish, "remove-publish", "", "Unpublish a container's port(s) to the host")

	return cmd
}

func runUpdate(ctx context.Context, dockerCli command.Cli, options *updateOptions) error {
	var err error

	if options.nFlag == 0 {
		return errors.New("you must provide one or more flags when using this command")
	}

	var restartPolicy containertypes.RestartPolicy
	if options.restartPolicy != "" {
		restartPolicy, err = opts.ParseRestartPolicy(options.restartPolicy)
		if err != nil {
			return err
		}
	}

	// var hostPort string
	// if options.removePublish != "" {
	// 	// remove extraneous whitespace
	// 	hostPort = strings.TrimSpace(options.removePublish)
	// 	// declare two uint64 variables to store the start and end of the port range
	// 	if len(hostPort) > 0 {
	// 		_, _, err = nat.ParsePortRange(hostPort)
	// 		if err != nil {
	// 			return err
	// 		}
	// 	}
	// }

	resources := containertypes.Resources{
		BlkioWeight:        options.blkioWeight,
		CpusetCpus:         options.cpusetCpus,
		CpusetMems:         options.cpusetMems,
		CPUShares:          options.cpuShares,
		Memory:             options.memory.Value(),
		MemoryReservation:  options.memoryReservation.Value(),
		MemorySwap:         options.memorySwap.Value(),
		KernelMemory:       options.kernelMemory.Value(),
		CPUPeriod:          options.cpuPeriod,
		CPUQuota:           options.cpuQuota,
		CPURealtimePeriod:  options.cpuRealtimePeriod,
		CPURealtimeRuntime: options.cpuRealtimeRuntime,
		NanoCPUs:           options.cpus.Value(),
	}

	if options.pidsLimit != 0 {
		resources.PidsLimit = &options.pidsLimit
	}

	updateConfig := containertypes.UpdateConfig{
		Resources:     resources,
		RestartPolicy: restartPolicy,
	}

	var (
		warns []string
		errs  []string
	)

	addPublishOpts := options.addPublish.GetAll()
	var (
		addPorts         map[nat.Port]struct{}
		addPortBindings  map[nat.Port][]nat.PortBinding
		addConvertedOpts []string
	)

	addConvertedOpts, err = convertToStandardNotation(addPublishOpts)
	if err != nil {
		errs = append(errs, err.Error())
	}

	addPorts, addPortBindings, err = nat.ParsePortSpecs(addConvertedOpts)
	if err != nil {
		errs = append(errs, err.Error())
	}

	fmt.Fprintln(dockerCli.Out(), "addPorts", addPorts)
	fmt.Fprintln(dockerCli.Out(), "addPortBindings", addPortBindings)

	removePublishOpts := options.removePublish.GetAll()
	var (
		removePorts         map[nat.Port]struct{}
		removePortBindings  map[nat.Port][]nat.PortBinding
		removeConvertedOpts []string
	)

	removeConvertedOpts, err = convertToStandardNotation(removePublishOpts)
	if err != nil {
		errs = append(errs, err.Error())
	}

	removePorts, removePortBindings, err = nat.ParsePortSpecs(removeConvertedOpts)
	if err != nil {
		errs = append(errs, err.Error())
	}

	fmt.Fprintln(dockerCli.Out(), "removePorts", removePorts)
	fmt.Fprintln(dockerCli.Out(), "removePortBindings", removePortBindings)

	// print the portBindings of each container
	for _, container := range options.containers {
		c, err := dockerCli.Client().ContainerInspect(ctx, container)
		if err != nil {
			return err
		}

		combinedPortBindings := c.HostConfig.PortBindings
		for from, frontend := range addPortBindings {
			combinedPortBindings[nat.Port(from)] = frontend
		}

		// // remove-publish
		// if hostPort != "" {
		// 	for port, portBinding := range combinedPortBindings {
		// 		if portBinding[0].HostPort == hostPort {
		// 			delete(combinedPortBindings, port)
		// 		}
		// 	}
		// }


		// PortBindings are together in combinedPortBindings
		fmt.Fprintln(dockerCli.Out(), container, combinedPortBindings)
		
		// for port, portBinding := range portBindings {
		// 	ip1 := "0.0.0.0"
		// 	ip2 := "::"
		// 	from := nat.Port(port)
		// 	frontends := []nat.PortBinding{{HostIP: ip1, HostPort: portBinding[0].HostPort}, {HostIP: ip2, HostPort: portBinding[0].HostPort}}
		// 	c.NetworkSettings.Ports[from] = frontends
		// }
	}

	for _, container := range options.containers {
		r, err := dockerCli.Client().ContainerUpdate(ctx, container, updateConfig)
		if err != nil {
			errs = append(errs, err.Error())
		} else {
			fmt.Fprintln(dockerCli.Out(), container)
		}
		warns = append(warns, r.Warnings...)
	}


	if len(warns) > 0 {
		fmt.Fprintln(dockerCli.Out(), strings.Join(warns, "\n"))
	}
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "\n"))
	}
	return nil
}
