// Copyright 2014 CNI authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"encoding/json"
	"fmt"
	"runtime"

	"github.com/containernetworking/cni/pkg/ip"
	"github.com/containernetworking/cni/pkg/ns"
	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	"github.com/containernetworking/cni/pkg/types/current"
	"github.com/containernetworking/cni/pkg/version"
)

const defaultBrName = "cni0"

type NetConf struct {
	types.NetConf
	PrevResult    *current.Result        `json:"prevResult,omitempty"`
	BrName        string                 `json:"bridge"`
	IsGW          bool                   `json:"isGateway"`
	IsDefaultGW   bool                   `json:"isDefaultGateway"`
	ForceAddress  bool                   `json:"forceAddress"`
	IPMasq        bool                   `json:"ipMasq"`
	MTU           int                    `json:"mtu"`
	HairpinMode   bool                   `json:"hairpinMode"`
	RuntimeConfig map[string]interface{} `json:"runtimeConfig"`
}

func init() {
	// this ensures that main runs only on main thread (thread group leader).
	// since namespace ops (unshare, setns) are done for a single thread, we
	// must ensure that the goroutine does not jump from OS thread to thread
	runtime.LockOSThread()
}

func loadNetConf(bytes []byte) (*NetConf, string, error) {
	n := &NetConf{
		BrName: defaultBrName,
	}
	if err := json.Unmarshal(bytes, n); err != nil {
		return nil, "", fmt.Errorf("failed to load netconf: %v", err)
	}
	return n, n.CNIVersion, nil
}

func setupTap(netns ns.NetNS, ifName string, mtu int) (*current.Interface, *current.Interface, error) {
	iface := &current.Interface{}
	hostIface := &current.Interface{}

	// create a tap interface, this remains on the host side
	// and hence needs a unique non conflicting name
	// The desired name is embedded in the alias
	tapName, err := ip.RandomVethName()
	if err != nil {
		return nil, nil, err
	}

	tap, err := ip.SetupTap(tapName, mtu, netns)
	if err != nil {
		return nil, nil, err
	}

	// Store the desired name and sandbox ID in the alias
	// This will help identify the interface on the host
	// when the interface needs to be deleted
	alias := ifName + "_" + netns.Path()
	err = ip.SetAlias(tap, alias)
	if err != nil {
		return nil, nil, err
	}

	iface.Name = ifName
	iface.Mac = tap.Attrs().HardwareAddr.String()
	iface.Sandbox = netns.Path()
	hostIface.Name = tap.Attrs().Name

	return hostIface, iface, nil
}

func cmdAdd(args *skel.CmdArgs) error {
	var hostInterface, containerInterface *current.Interface
	var isVMRuntime bool
	n, cniVersion, err := loadNetConf(args.StdinData)
	if err != nil {
		return err
	}

	if n.IsDefaultGW {
		n.IsGW = true
	}

	netns, err := ns.GetNS(args.Netns)
	if err != nil {
		return fmt.Errorf("failed to open netns %q: %v", args.Netns, err)
	}
	defer netns.Close()

	vmRuntime, ok := n.RuntimeConfig["configureVM"]
	if ok {
		isVMRuntime, ok = vmRuntime.(bool)
	}

	if !isVMRuntime {
		newResult, err := current.NewResultFromResult(n.PrevResult)
		if err != nil {
			return err
		}
		return types.PrintResult(newResult, cniVersion)
	}

	hostInterface, containerInterface, err = setupTap(netns, args.IfName, n.MTU)
	if err != nil {
		return err
	}

	result := &current.Result{}
	result.Interfaces = []*current.Interface{hostInterface, containerInterface}

	return types.PrintResult(result, cniVersion)
}

func cmdDel(args *skel.CmdArgs) error {
	_, _, err := loadNetConf(args.StdinData)
	if err != nil {
		return err
	}

	if args.Netns == "" {
		return nil
	}

	// There is a netns so try to clean up. Delete can be called multiple times
	// so don't return an error if the device is already removed.
	// If the device isn't there then don't try to clean up IP masq either.
	err = ns.WithNetNSPath(args.Netns, func(_ ns.NetNS) error {
		err = ip.DelLinkByName(args.IfName)
		if err != nil {
			return nil
		}
		return err
	})

	return err
}

func main() {
	skel.PluginMain(cmdAdd, cmdDel, version.All)
}
