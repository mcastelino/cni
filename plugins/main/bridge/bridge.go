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

	"github.com/containernetworking/cni/pkg/bridge"
	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	"github.com/containernetworking/cni/pkg/types/current"
	"github.com/containernetworking/cni/pkg/version"
	"github.com/vishvananda/netlink"
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

func cmdAdd(args *skel.CmdArgs) error {
	var hostInterface, containerInterface *current.Interface
	n, cniVersion, err := loadNetConf(args.StdinData)
	if err != nil {
		return err
	}

	if n.IsDefaultGW {
		n.IsGW = true
	}

	newResult, err := current.NewResultFromResult(n.PrevResult)
	if err != nil {
		return err
	}

	if newResult.Interfaces == nil || len(newResult.Interfaces) < 2 {
		return fmt.Errorf("invalid plugin chain, expected interfaces %v", newResult)
	}

	hostInterface = newResult.Interfaces[0]
	containerInterface = newResult.Interfaces[1]

	if hostInterface == nil || containerInterface == nil {
		return fmt.Errorf("invalid interface %v", newResult)
	}

	br, brInterface, err := bridge.Setup(n.BrName, n.MTU)
	if err != nil {
		return err
	}

	// Rebuild the interface list prepending the bridge
	newResult.Interfaces = []*current.Interface{brInterface, hostInterface, containerInterface}

	// connect host interface to the bridge
	hostLink, err := netlink.LinkByName(hostInterface.Name)
	if err != nil {
		return err
	}
	if err := netlink.LinkSetMaster(hostLink, br); err != nil {
		return fmt.Errorf("failed to connect %q to bridge %v: %v", hostLink.Attrs().Name, br.Attrs().Name, err)
	}

	// set hairpin mode (we are setting a interface property in the bridge
	// TODO: this feel wrong, but it cannot be sent
	if err = netlink.LinkSetHairpin(hostLink, n.HairpinMode); err != nil {
		return fmt.Errorf("failed to setup hairpin mode for %v: %v", hostLink.Attrs().Name, err)
	}

	return types.PrintResult(newResult, cniVersion)
}

func cmdDel(args *skel.CmdArgs) error {
	_, _, err := loadNetConf(args.StdinData)
	if err != nil {
		return err
	}

	return nil
}

func main() {
	skel.PluginMain(cmdAdd, cmdDel, version.All)
}
