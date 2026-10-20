package cluster

// A skipped enrol unit does not fail k3s, so a reboot after enrolment neither repeats it nor blocks k3s.
const enrolUnitFile = `[Unit]
Description=Enrol this cluster with the mitstack platform
Wants=network-online.target
After=network-online.target
Before=k3s.service
ConditionPathExists=!/etc/mitstack/enrolment.json

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=` + enrolScriptPath + `
`

const k3sEnrolmentDropIn = `[Unit]
Requires=` + EnrolUnit + `
After=` + EnrolUnit + `
`

// The table is declared, deleted and redefined in one atomic load, so a rerun replaces it and leaves k3s's and Cilium's tables alone.
const metadataGuardRules = `# Drops pod traffic to the Hetzner metadata service; loaded by ` + guardUnit + `.
table inet mitstack_metadata_guard
delete table inet mitstack_metadata_guard
table inet mitstack_metadata_guard {
	chain forward {
		type filter hook forward priority -10; policy accept;
		ip daddr 169.254.169.254 counter drop
	}
}
`

// RemainAfterExit keeps the guard unit active after nft exits, so k3s's Requires= holds.
const guardUnitFile = `[Unit]
Description=Drop pod traffic to the Hetzner metadata service
Before=k3s.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/sbin/nft -f ` + guardRulesPath + `

[Install]
WantedBy=multi-user.target
`

const k3sGuardDropIn = `[Unit]
Requires=` + guardUnit + `
After=` + guardUnit + `
`
