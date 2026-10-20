package cluster

// The apt settings run unattended-upgrades at 01:30 UTC, before kured's reboot window, and leave every reboot to kured, which drains first.
const aptDailyUpgradeWindow = `[Timer]
OnCalendar=
OnCalendar=*-*-* 01:30:00 UTC
RandomizedDelaySec=0
`

const unattendedUpgradesConfig = `APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
Unattended-Upgrade::Allowed-Origins {
	"${distro_id}:${distro_codename}-updates";
};
Unattended-Upgrade::Automatic-Reboot "false";
`
