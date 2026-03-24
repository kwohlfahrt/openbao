// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package catalog

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-plugin"
	gkwplugin "github.com/openbao/go-kms-wrapping/plugin/v2"
	"github.com/openbao/openbao/api/v2"
	"github.com/openbao/openbao/command/server"
	"github.com/openbao/openbao/helper/osutil"
	"github.com/openbao/openbao/helper/pluginutil/oci"
	"github.com/openbao/openbao/sdk/v2/helper/consts"
)

type Constructor[T interface{}] func(interface{}) (*T, error)
type Builtins[T interface{}] map[string]func() (*T, error)

// Catalog manages dispatches to builtin and external KMS plugins and manages
// their processes & connections. This is disjoint from the "main" plugin
// catalog in core as KMS plugins may need to be instantiated before core is
// created. Additionally, we get to simplify many things as KMS plugins are
// declarative only.
type Catalog[T interface{}] struct {
	logger hclog.Logger

	mu          sync.Mutex
	plugins     map[string]*server.PluginConfig
	clients     map[string]*Client
	builtins    Builtins[T]
	constructor Constructor[T]
	pluginType  consts.PluginType

	// Derived from server configuration.
	pluginDirectory       string
	pluginFileUid         int
	pluginFilePermissions int
}

// The interfaces of the Catalog required by the client, exists so that the
// Client doesn't need to be generic.
type clientCatalog interface {
	lock()
	unlock()

	removeClientLocked(client *Client)
}

// NewCatalog returns a new KMS plugin catalog.
func NewCatalog[T interface{}](
	logger hclog.Logger,
	config *server.Config,
	pluginType consts.PluginType,
	builtins Builtins[T],
	constructor Constructor[T],
) (*Catalog[T], error) {
	pluginDirectory := config.PluginDirectory
	if pluginDirectory != "" {
		var err error
		pluginDirectory, err = filepath.Abs(pluginDirectory)
		if err != nil {
			return nil, fmt.Errorf("expand plugin directory: %w", err)
		}
		pluginDirectory, err = filepath.EvalSymlinks(pluginDirectory)
		if err != nil {
			return nil, fmt.Errorf("expand plugin directory: %w", err)
		}
	}

	// Index plugin configs by name for easy lookup and to ensure there are no
	// naming conflicts.
	plugins := make(map[string]*server.PluginConfig)
	for _, plugin := range config.Plugins {
		// Ignore plugins that aren't type KMS.
		if typ, _ := consts.ParsePluginType(plugin.Type); typ != pluginType {
			continue
		}
		// For now, KMS plugins only support one version at a time.
		if _, ok := plugins[plugin.Name]; ok {
			return nil, fmt.Errorf("cannot register several versions of plugin %q", plugin.Name)
		}
		plugins[plugin.Name] = plugin
	}

	return &Catalog[T]{
		logger:                logger.Named(pluginType.String()),
		plugins:               plugins,
		clients:               make(map[string]*Client, len(plugins)),
		builtins:              builtins,
		pluginType:            pluginType,
		constructor:           constructor,
		pluginDirectory:       pluginDirectory,
		pluginFileUid:         config.PluginFileUid,
		pluginFilePermissions: config.PluginFilePermissions,
	}, nil
}

func (c *Catalog[T]) GetPlugin(name string) (*T, bool, error) {
	client, ok, err := c.getClient(name)
	if err != nil {
		return nil, false, err
	}
	if !ok {
		if factory, ok := c.builtins[name]; ok {
			p, err := factory()
			return p, true, err
		}
		return nil, false, fmt.Errorf("unknown %s plugin: %s", c.pluginType.String(), name)
	}

	raw, err := client.Dispense("TODO")
	if err != nil {
		client.Close()
		return nil, false, err
	}

	plugin, err := c.constructor(raw)
	return plugin, false, err
}

func (c *Catalog[T]) lock() {
	c.mu.Lock()
}

func (c *Catalog[T]) unlock() {
	c.mu.Unlock()
}

func (c *Catalog[T]) removeClientLocked(client *Client) {
	if stored, ok := c.clients[client.name]; ok && stored == client {
		delete(c.clients, client.name)
	}
}

func (c *Catalog[T]) getClient(name string) (*Client, bool, error) {
	c.lock()
	defer c.unlock()

	return c.getClientLocked(name)
}

func (c *Catalog[T]) getClientLocked(name string) (*Client, bool, error) {
	// Try to reuse an existing client.
	if cl, ok := c.clients[name]; ok {
		cl.refs++
		return cl, true, nil
	}

	// Check for plugin configuration.
	config, ok := c.plugins[name]
	if !ok {
		return nil, false, nil
	}

	// Don't continue with external plugins if no plugin directory is set.
	if c.pluginDirectory == "" {
		return nil, true, errors.New("plugin directory not configured")
	}

	if err := c.checkFilePath(config); err != nil {
		return nil, true, err
	}

	checksum, err := hex.DecodeString(config.SHA256Sum)
	if err != nil {
		return nil, true, fmt.Errorf("invalid plugin sha256: %w", err)
	}

	// Spawn a new plugin process.
	exe := filepath.Join(c.pluginDirectory, config.CommandPath())
	cmd := exec.Command(exe, config.Args...)
	cmd.Env = append(cmd.Env, config.Env...)

	process := plugin.NewClient(&plugin.ClientConfig{
		Cmd:              cmd,
		VersionedPlugins: gkwplugin.PluginSets,
		HandshakeConfig:  gkwplugin.HandshakeConfig,
		AllowedProtocols: []plugin.Protocol{plugin.ProtocolGRPC},
		AutoMTLS:         true,
		Logger:           c.logger.Named(name),
		SecureConfig: &plugin.SecureConfig{
			Checksum: checksum,
			Hash:     sha256.New(),
		},
	})

	proto, err := process.Client()
	if err != nil {
		process.Kill()
		return nil, true, fmt.Errorf("start plugin client: %w", err)
	}

	cl := &Client{
		catalog:        c,
		name:           name,
		refs:           1,
		process:        process,
		ClientProtocol: proto,
	}
	c.clients[name] = cl
	return cl, true, nil
}

func (c *Catalog[T]) reloadClient(prev *Client) (*Client, error) {
	c.lock()
	defer c.unlock()

	client, ok, err := c.getClientLocked(prev.name)
	switch {
	case err != nil:
		return nil, err
	case !ok:
		return nil, fmt.Errorf("unknown plugin: %s", prev.name)
	}

	if client != prev {
		// This client was already reloaded, its address changed.
		return client, nil
	}

	// Call this for good measure - reloadClient should typically only be called
	// if the client is already known dead.
	prev.process.Kill()

	// Force a client recreation.
	delete(c.clients, prev.name)
	client, ok, err = c.getClientLocked(prev.name)
	switch {
	case err != nil:
		return nil, err
	case !ok:
		return nil, fmt.Errorf("unknown plugin: %s", prev.name)
	}

	return client, nil
}

// checkFilePath mirrors path & permission checks performed by the core plugin
// catalog.
func (c *Catalog[T]) checkFilePath(plugin *server.PluginConfig) error {
	// Best effort check to make sure the command isn't breaking out of the
	// configured plugin directory.
	path, err := filepath.EvalSymlinks(filepath.Join(c.pluginDirectory, plugin.CommandPath()))
	if err != nil {
		return fmt.Errorf("error while validating the command path: %w", err)
	}

	var ok bool
	if plugin.Image == "" {
		// Declarative, manual plugin.
		ok = filepath.Dir(path) == c.pluginDirectory
	} else {
		// Declarative, OCI-based plugin.
		ok = filepath.Dir(path) == filepath.Join(
			c.pluginDirectory, oci.PluginCacheDir, plugin.Slug(), plugin.SHA256Sum[:8])
	}
	if !ok {
		return errors.New("cannot execute files outside of configured plugin directory")
	}

	if env := api.ReadBaoVariable(consts.VaultEnableFilePermissionsCheckEnv); env != "" {
		enable, err := strconv.ParseBool(env)
		switch {
		case err != nil:
			return fmt.Errorf("failed to parse environment variable %s", consts.VaultEnableFilePermissionsCheckEnv)
		case enable:
			return osutil.OwnerPermissionsMatch(path, c.pluginFileUid, c.pluginFilePermissions)
		}
	}

	return nil
}

type Client struct {
	catalog clientCatalog

	name string // Name of the plugin.
	refs int    // Reference count.

	process *plugin.Client
	plugin.ClientProtocol
}

// close decrements the client's reference count and kills it if the reference
// count reaches zero.
func (c *Client) Close() {
	c.catalog.lock()
	defer c.catalog.unlock()

	if c.refs == 0 {
		panic("kmsplugin: tried to close client more than once")
	}

	c.refs--
	if c.refs != 0 {
		// Client remains live.
		return
	}

	// Last reference, so kill the process.
	c.process.Kill()

	// Remove from lookup if this is still the most recent client.
	c.catalog.removeClientLocked(c)
}
