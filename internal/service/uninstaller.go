package service

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/rs/zerolog"
	"github.com/serjseiche/antiscan/internal/state"
)

// UninstallerService reverts AntiscanSimple-managed system changes.
type UninstallerService struct {
	logger      zerolog.Logger
	cmdSvc      *CommandService
	iptablesCmd *IptablesCommandService
	ipsetCmd    *IpsetCommandService
}

// NewUninstallerService creates a new uninstaller service.
func NewUninstallerService(logger zerolog.Logger, cmdSvc *CommandService) *UninstallerService {
	return &UninstallerService{
		logger:      logger,
		cmdSvc:      cmdSvc,
		iptablesCmd: NewIptablesCommandService(logger, cmdSvc),
		ipsetCmd:    NewIpsetCommandService(logger, cmdSvc),
	}
}

// Uninstall removes AntiscanSimple artifacts and restores firewall state.
//
// LIMITATION: Any iptables rules that existed before running "antiscan-simple
// full" are not preserved. The "full" command flushed and replaced the
// SCANNERS-BLOCK chain and saved the resulting ruleset. After uninstall the
// saved ruleset (/etc/iptables/rules.v4) will reflect the post-full state
// minus the SCANNERS-BLOCK chain — it will not match what was present before
// the initial install. Users who had custom iptables rules should restore them
// manually from a backup after uninstalling.
func (s *UninstallerService) Uninstall(removeLogs bool) error {
	s.logger.Info().Msg("=== Uninstalling AntiscanSimple ===")
	s.logger.Info().Msg("AntiscanSimple does not modify Linux routing tables (ip rule/ip route) — skipping routing rollback")
	s.logger.Warn().Msg("NOTE: pre-existing iptables rules from before the initial install are not restored — restore them manually from a backup if needed")

	s.stopAndDisableServices()
	s.cleanupIPTablesRuntime()
	s.cleanupIPSet()
	s.removeArtifacts(removeLogs)

	if err := s.reloadSystemdDaemon(); err != nil {
		s.logger.Warn().Err(err).Msg("Failed to reload systemd daemon")
	}

	if err := s.persistFirewallState(); err != nil {
		return fmt.Errorf("failed to persist firewall state: %w", err)
	}

	s.logger.Info().Msg("AntiscanSimple uninstall completed")
	return nil
}

func (s *UninstallerService) stopAndDisableServices() {
	if !s.cmdSvc.CommandExists("systemctl") {
		s.logger.Warn().Msg("systemctl not found, skipping service stop/disable")
		return
	}

	services := []string{
		"antiscan-simple-update.timer",
		"antiscan-simple-update.service",
		"antiscan-aggregate.timer",
		"antiscan-aggregate.service",
		"antiscan-ipset-restore.service",
		"antiscan-docker-rules.timer",
		"antiscan-docker-rules.service",
	}

	for _, serviceName := range services {
		if err := s.cmdSvc.StopService(serviceName); err != nil {
			s.logger.Warn().Err(err).Str("service", serviceName).Msg("Stop failed, continuing")
		}
		if err := s.cmdSvc.DisableService(serviceName); err != nil {
			s.logger.Warn().Err(err).Str("service", serviceName).Msg("Disable failed, continuing")
		}
	}
}

func (s *UninstallerService) cleanupIPTablesRuntime() {
	s.cleanupIPTablesVersion(IPv4)
	s.cleanupDockerUser()
}

func (s *UninstallerService) cleanupDockerUser() {
	rules := [][]string{
		{"-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "RETURN"},
		{"-m", "set", "--match-set", ipsetV4Name, "src", "-j", "DROP"},
	}
	for _, rule := range rules {
		if s.iptablesCmd.RuleExists(IPv4, TableFilter, "DOCKER-USER", rule) {
			if err := s.iptablesCmd.DeleteRule(IPv4, TableFilter, "DOCKER-USER", rule); err != nil {
				s.logger.Warn().Err(err).Msg("Failed to remove rule from DOCKER-USER, continuing")
			} else {
				s.logger.Info().Msg("Rule removed from DOCKER-USER")
			}
		}
	}
}

func (s *UninstallerService) cleanupIPTablesVersion(version IPVersion) {
	if err := s.iptablesCmd.UnlinkChainFromInput(version, chainName); err != nil {
		s.logger.Warn().Err(err).Str("version", string(version)).Msg("Failed to unlink chain from INPUT, continuing")
	}

	if !s.iptablesCmd.ChainExists(version, TableFilter, chainName) {
		return
	}

	if err := s.iptablesCmd.FlushChain(version, TableFilter, chainName); err != nil {
		s.logger.Warn().Err(err).Str("version", string(version)).Msg("Failed to flush chain, continuing")
	}

	if err := s.iptablesCmd.DeleteChain(version, TableFilter, chainName); err != nil {
		s.logger.Warn().Err(err).Str("version", string(version)).Msg("Failed to delete chain, continuing")
	}
}

func (s *UninstallerService) cleanupIPSet() {
	for _, setName := range []string{ipsetV4Name} {
		if !s.ipsetCmd.Exists(setName) {
			continue
		}

		if err := s.ipsetCmd.Flush(setName); err != nil {
			s.logger.Warn().Err(err).Str("set", setName).Msg("Failed to flush ipset, continuing")
		}
		if err := s.ipsetCmd.Destroy(setName); err != nil {
			s.logger.Warn().Err(err).Str("set", setName).Msg("Failed to destroy ipset, continuing")
		}
	}

	if err := removeFileIfExists(IpsetConfigPath); err != nil {
		s.logger.Warn().Err(err).Str("path", IpsetConfigPath).Msg("Failed to remove ipset config")
	}
}

func (s *UninstallerService) removeArtifacts(removeLogs bool) {
	paths := []string{
		IpsetRestoreServicePath,
		AggregateLogsServicePath,
		AggregateLogsTimerPath,
		AggregateLogsScriptPath,
		LogrotateConfigPath,
		UpdateServicePath,
		UpdateTimerPath,
		DockerRulesServicePath,
		DockerRulesTimerPath,
	}

	for _, path := range paths {
		if err := removeFileIfExists(path); err != nil {
			s.logger.Warn().Err(err).Str("path", path).Msg("Failed to remove file, continuing")
		}
	}

	if err := state.Remove(); err != nil {
		s.logger.Warn().Err(err).Str("path", state.Path()).Msg("Failed to remove state file, continuing")
	}
	if err := state.RemoveDir(); err != nil {
		s.logger.Debug().Err(err).Msg("State directory not removed (likely not empty)")
	}

	if err := os.RemoveAll(filepath.Dir(JournalCursorPath)); err != nil && !os.IsNotExist(err) {
		s.logger.Warn().Err(err).Str("path", filepath.Dir(JournalCursorPath)).Msg("Failed to remove journal cursor directory, continuing")
	}

	if !removeLogs {
		return
	}

	logFiles, err := filepath.Glob("/var/log/iptables-scanners-*")
	if err != nil {
		s.logger.Warn().Err(err).Msg("Failed to enumerate log files")
		return
	}

	for _, logFile := range logFiles {
		if err := removeFileIfExists(logFile); err != nil {
			s.logger.Warn().Err(err).Str("path", logFile).Msg("Failed to remove log file")
		}
	}
}

func (s *UninstallerService) reloadSystemdDaemon() error {
	if !s.cmdSvc.CommandExists("systemctl") {
		return nil
	}

	return s.cmdSvc.DaemonReload()
}

func (s *UninstallerService) persistFirewallState() error {
	s.logger.Info().Msg("Persisting firewall state to /etc/iptables/")

	if err := os.MkdirAll("/etc/iptables", 0755); err != nil {
		return err
	}

	if err := s.iptablesCmd.Save(IPv4, IptablesRulesV4Path); err != nil {
		return err
	}

	if s.cmdSvc.CommandExists("netfilter-persistent") {
		if err := s.cmdSvc.Run("netfilter-persistent", "save"); err != nil {
			s.logger.Warn().Err(err).Msg("netfilter-persistent save failed")
		}
	}

	return nil
}

func removeFileIfExists(path string) error {
	err := os.Remove(path)
	if err == nil || os.IsNotExist(err) {
		return nil
	}
	return err
}
