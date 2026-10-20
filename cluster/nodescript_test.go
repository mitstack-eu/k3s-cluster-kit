package cluster

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"go.yaml.in/yaml/v3"
)

const hetznerPrivateNetworks = "- ip: 10.255.0.2\n  alias_ips: [10.255.0.9]\n  interface_num: 1\n  mac_address: 86:00:00:2a:7d:e0\n" +
	"  network_id: 3001\n  network_name: orbitdemo-abcd2345\n  network: 10.0.0.0/8\n  subnet: 10.255.0.0/16\n  gateway: 10.0.0.1\n"

func TestNodeScript_Contract(t *testing.T) {
	_, cc := renderFixture(t)
	assertNamesAll(t, "the node script", cc.nodeScript(t).Content, "http://169.254.169.254/hetzner/v1/metadata",
		"/etc/rancher/k3s/config.yaml.d", dropInFile, nodeScriptMetadataEnv, nodeScriptDropInEnv)
}

func TestNodeScript_AgainstTheMetadataService(t *testing.T) {
	_, cc := renderFixture(t)
	script := cc.nodeScript(t).Content
	dropIn := func(id, ip string) map[string]any {
		return map[string]any{"node-ip": ip, "advertise-address": ip, "bind-address": ip, "kubelet-arg+": []any{"provider-id=hcloud://" + id}}
	}
	cases := []struct {
		name, id, networks string
		failFirst          map[string]int
		bound              time.Duration
		want               map[string]any
		minHits            map[string]int
	}{
		{"writes the provider id and private IP from the metadata service", "123456\n", hetznerPrivateNetworks, nil, time.Minute,
			dropIn("123456", "10.255.0.2"), map[string]int{"instance-id": 1, "private-networks": 1}},
		{"binds k3s to the private IP it advertises, whichever it is", "7654321\n", "- ip: 10.0.3.4\n  network_id: 4002\n  subnet: 10.0.3.0/24\n", nil, time.Minute,
			dropIn("7654321", "10.0.3.4"), nil},
		{"retries until the metadata service answers", "123456\n", hetznerPrivateNetworks, map[string]int{"instance-id": 2, "private-networks": 1}, 2 * time.Minute,
			dropIn("123456", "10.255.0.2"), map[string]int{"instance-id": 3, "private-networks": 2}},
		{"fails on a non-numeric server id", "i-12ab\n", hetznerPrivateNetworks, nil, time.Minute, nil, nil},
		{"fails when the server has no private IP", "123456\n", "[]\n", nil, time.Minute, nil, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			md := newFakeMetadata(t, map[string]metadataAnswer{
				metadataPath + "/instance-id":      {body: tc.id, failFirst: tc.failFirst["instance-id"]},
				metadataPath + "/private-networks": {body: tc.networks, failFirst: tc.failFirst["private-networks"]},
			})

			dir, run := runNodeScript(t, script, md, tc.bound)

			raw, readErr := os.ReadFile(filepath.Join(dir, dropInFile))
			if tc.want == nil {
				var exit *exec.ExitError
				fatalIf(t, !errors.As(run.err, &exit), "the node script with server id %q and networks %q error = %v; want a non-zero exit\n%s", tc.id, tc.networks, run.err, run.output())
				failIf(t, readErr == nil, "the node script with server id %q and networks %q wrote %s despite failing; want no file", tc.id, tc.networks, dropInFile)
				return
			}
			fatalIf(t, run.err != nil || readErr != nil, "the node script with server id %q and networks %q failed (run %v, read %v); want success\n%s", tc.id, tc.networks, run.err, readErr, run.output())
			var got map[string]any
			err := yaml.Unmarshal(raw, &got)
			fatalIf(t, err != nil, "%s is not valid YAML: %v\n%s", dropInFile, err, raw)
			failIf(t, !reflect.DeepEqual(got, tc.want), "%s = %#v; want %#v", dropInFile, got, tc.want)
			for _, endpoint := range mapKeys(tc.minHits) {
				n := md.hitCount(metadataPath + "/" + endpoint)
				failIf(t, n < tc.minHits[endpoint], "%s was read %d times; want at least %d", endpoint, n, tc.minHits[endpoint])
			}
		})
	}
}
