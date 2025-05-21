package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/hashicorp/go-discover"
	"github.com/hashicorp/go-discover/provider/k8s"
	"github.com/hashicorp/go-plugin"
	"github.com/openbao/openbao/sdk/v2/joinPlugin"
)

func newDiscover() (*discover.Discover, error) {
	providers := make(map[string]discover.Provider)
	for k, v := range discover.Providers {
		providers[k] = v
	}
	providers["k8s"] = &k8s.Provider{}
	return discover.New(discover.WithProviders(providers))
}

type Discover struct {
	disco *discover.Discover
}

func (d *Discover) Candidates(config map[string]string) ([]joinPlugin.Addr, error) {
	args, found := config["discover"]
	if !found {
		return nil, fmt.Errorf("`discover` string must be provided")
	}

	portStr := config["port"]
	if portStr == "" {
		portStr = "8200"
	}
	port, err := strconv.ParseUint(config["port"], 10, 16)
	if err != nil {
		return nil, fmt.Errorf("invalid `port`: %s", portStr)
	}
	scheme := config["scheme"]
	if scheme == "" {
		scheme = "https"
	}

	ips, err := d.disco.Addrs(args, nil) // TODO: logging
	if err != nil {
		return nil, err
	}

	addrs := make([]joinPlugin.Addr, len(ips))
	for _, ip := range ips {
		if strings.Count(ip, ":") >= 2 && !strings.HasPrefix(ip, "[") {
			// An IPv6 address in implicit form, however we need it in explicit form to use in a URL.
			ip = fmt.Sprintf("[%s]", ip)
		}
		addrs = append(addrs, joinPlugin.Addr{Scheme: scheme, Host: ip, Port: uint16(port)})
	}

	return addrs, nil
}

func Run() error {
	disco, err := newDiscover()
	if err != nil {
		return err
	}
	plugin.Serve(&plugin.ServeConfig{
		HandshakeConfig: joinPlugin.HandshakeConfig,
		Plugins: map[string]plugin.Plugin{
			"discover": joinPlugin.JoinPlugin{Impl: &Discover{disco: disco}},
		},
		GRPCServer: plugin.DefaultGRPCServer,
	})
	return nil
}

func main() {
	err := Run()
	if err != nil {
		os.Exit(1)
	}
}
