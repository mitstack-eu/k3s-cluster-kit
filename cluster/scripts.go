package cluster

import (
	"embed"
	"strings"
	"text/template"
)

//go:embed scripts/refusal-reason.sh scripts/mitstack-enrol.sh scripts/mitstack-install-k3s.sh scripts/mitstack-hcloud-node.sh scripts/nodeagent/node-agent.yaml scripts/nodeagent/digest
var scriptFiles embed.FS

func script(name string) string {
	raw, err := scriptFiles.ReadFile("scripts/" + name)
	if err != nil {
		panic(err)
	}
	return string(raw)
}

const (
	// A script names a value spliced in at @NAME@; @REFUSAL_REASON@ spans its line so the blank lines around it survive, and fragmentShebang lets refusal-reason.sh lint alone and is dropped where it is spliced in.
	refusalReasonPlaceholder  = "@REFUSAL_REASON@\n"
	nodeAgentImagePlaceholder = "@NODE_AGENT_IMAGE@"
	fragmentShebang           = "#!/bin/sh\n"
)

var (
	refusalReasonFunc = strings.TrimPrefix(script("refusal-reason.sh"), fragmentShebang)
	enrolScript       = strings.Replace(script("mitstack-enrol.sh"), refusalReasonPlaceholder, refusalReasonFunc, 1)
	nodeScript        = script("mitstack-hcloud-node.sh")
	installerScript   = template.Must(template.New("installer").Parse(script("mitstack-install-k3s.sh")))
)
