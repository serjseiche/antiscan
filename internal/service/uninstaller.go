package service

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/serj1974-maker/antiscan/internal/state"
	"github.com/rs/zerolog"
)

// UninstallerService reverts TrafficGuard-managed system changes.
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

// Uninstall removes TrafficGuard artifacts and restores firewall state.
func (s *UninstallerService) Uninstall(removeLogs bool) error {
	s.logger.Info().Msg("=== Uninstall TrafficGuard ===")
	s.logger.Info().Msg("TrafficGuard does not modify Linux routing tables (ip rule/ip route), skipping routing rollback")

	s.stopAndDisableServices()
	s.cleanupIPTablesRuntime()
	s.cleanupIPSet()
	s.removeArtifacts(removeLogs)

	if err := s.reloadSystemdDaemon(); err != nil {
		s.logger.Warn().Err(err).Msg("Failed to reload systemd daemon")
	}

	if err := s.reloadRsyslog(); err != nil {
		s.logger.Warn().Err(err).Msg("Failed to reload rsyslog")
	}

	if err := s.persistFirewallState(); err != nil {
		return fmt.Errorf("failed to persist firewall state: %w", err)
	}

	s.logger.Info().Msg("TrafficGuard uninstall completed")
	return nil
}

func (s *UninstallerService) stopAndDisableServices() {
	if !s.cmdSvc.CommandExists("systemctl") {
		s.logger.Warn().Msg("systemctl not found, skipping service stop/disable")
		return
	}

	services := []string{
		"traffic-guard-update.timer",
		"traffic-guard-update.service",
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
	dropRule := []string{"-m", "set", "--match-set", ipsetV4Name, "src", "-j", "DROP"}
	if s.iptablesCmd.RuleExists(IPv4, TableFilter, "DOCKER-USER", dropRule) {
		if err := s.iptablesCmd.DeleteRule(IPv4, TableFilter, "DOCKER-USER", dropRule); err != nil {
			s.logger.Warn().Err(err).Msg("Не удалось удалить правило из DOCKER-USER, продолжаем")
		} else {
			s.logger.Info().Msg("Правило удалено из DOCKER-USER")
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
		RsyslogConfigPath,
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

func (s *UninstallerService) reloadRsyslog() error {
	if !s.cmdSvc.CommandExists("systemctl") {
		return nil
	}

	// Check if rsyslog service exists and is active
	if err := s.cmdSvc.Run("systemctl", "is-active", "rsyslog"); err != nil {
		s.logger.Debug().Msg("rsyslog is not active, skipping reload")
		return nil
	}

	return s.cmdSvc.RestartService("rsyslog")
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
