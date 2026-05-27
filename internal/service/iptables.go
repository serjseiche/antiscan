package service

import (
	"fmt"
	"os"

	"github.com/rs/zerolog"
)

const (
	chainName = "SCANNERS-BLOCK"
)

// IptablesService handles iptables operations
type IptablesService struct {
	logger        zerolog.Logger
	enableLogging bool
	cmdSvc        *CommandService
	iptablesCmd   *IptablesCommandService
}

// NewIptablesService creates a new iptables service
func NewIptablesService(logger zerolog.Logger, cmdSvc *CommandService, enableLogging bool) *IptablesService {
	return &IptablesService{
		logger:        logger,
		enableLogging: enableLogging,
		cmdSvc:        cmdSvc,
		iptablesCmd:   NewIptablesCommandService(logger, cmdSvc),
	}
}

// SetupChain creates and configures iptables chains
func (s *IptablesService) SetupChain() error {
	s.logger.Info().Msg("Setting up iptables chains")

	if err := s.setupVersionChain(IPv4, ipsetV4Name, true); err != nil {
		return fmt.Errorf("failed to setup IPv4 chain: %w", err)
	}

	if s.isDockerPresent() {
		if err := s.setupDockerUserChain(); err != nil {
			s.logger.Warn().Err(err).Msg("Failed to configure DOCKER-USER, continuing")
		}
	} else {
		s.logger.Info().Msg("Docker not detected, skipping DOCKER-USER setup")
	}

	s.logger.Info().Msg("iptables chains configured")
	return nil
}

const dockerUserChain = "DOCKER-USER"

// isDockerPresent checks whether Docker is installed on the system.
func (s *IptablesService) isDockerPresent() bool {
	if s.cmdSvc.CommandExists("docker") {
		return true
	}
	_, err := os.Stat("/var/run/docker.sock")
	return err == nil
}

// setupDockerUserChain ensures SCANNERS-BLOCK-V4 is injected into DOCKER-USER.
// The chain is created if it does not exist (Docker may be installed later).
func (s *IptablesService) setupDockerUserChain() error {
	justCreated := false
	if !s.iptablesCmd.ChainExists(IPv4, TableFilter, dockerUserChain) {
		s.logger.Info().Msg("Creating DOCKER-USER chain")
		if err := s.iptablesCmd.CreateChain(IPv4, TableFilter, dockerUserChain); err != nil {
			return fmt.Errorf("failed to create DOCKER-USER: %w", err)
		}
		// Add RETURN at the end so Docker behaviour is preserved if it appears later
		if err := s.iptablesCmd.AppendRule(IPv4, TableFilter, dockerUserChain, []string{"-j", "RETURN"}); err != nil {
			s.logger.Warn().Err(err).Msg("Failed to add RETURN to DOCKER-USER")
		}
		justCreated = true
	}

	dropRule := []string{"-m", "set", "--match-set", ipsetV4Name, "src", "-j", "DROP"}
	if !s.iptablesCmd.RuleExists(IPv4, TableFilter, dockerUserChain, dropRule) {
		s.logger.Info().Msg("Inserting DROP rule into DOCKER-USER at position 1")
		if err := s.iptablesCmd.InsertRule(IPv4, TableFilter, dockerUserChain, 1, dropRule); err != nil {
			return fmt.Errorf("failed to add rule to DOCKER-USER: %w", err)
		}
	} else {
		s.logger.Debug().Bool("chain_created_now", justCreated).Msg("DOCKER-USER DROP rule already present")
	}

	if err := s.createDockerRuleService(); err != nil {
		s.logger.Warn().Err(err).Msg("Failed to create antiscan-docker-rules service")
	}
	return nil
}

// createDockerRuleService writes and enables antiscan-docker-rules.service and its timer.
func (s *IptablesService) createDockerRuleService() error {
	if err := os.WriteFile(DockerRulesServicePath, []byte(DockerRulesServiceTemplate), 0644); err != nil {
		return fmt.Errorf("write %s: %w", DockerRulesServicePath, err)
	}
	if err := os.WriteFile(DockerRulesTimerPath, []byte(DockerRulesTimerTemplate), 0644); err != nil {
		return fmt.Errorf("write %s: %w", DockerRulesTimerPath, err)
	}
	if err := s.cmdSvc.DaemonReload(); err != nil {
		s.logger.Warn().Err(err).Msg("daemon-reload failed")
	}
	if err := s.cmdSvc.EnableService("antiscan-docker-rules.service"); err != nil {
		return fmt.Errorf("enable antiscan-docker-rules.service: %w", err)
	}
	if err := s.cmdSvc.Run("systemctl", "enable", "--now", "antiscan-docker-rules.timer"); err != nil {
		s.logger.Warn().Err(err).Msg("Failed to enable antiscan-docker-rules.timer")
	}
	s.logger.Info().Msg("antiscan-docker-rules service and timer enabled")
	return nil
}

// setupVersionChain configures the SCANNERS-BLOCK chain
func (s *IptablesService) setupVersionChain(version IPVersion, ipsetName string, linkToInput bool) error {
	s.logger.Debug().Str("version", string(version)).Msg("Configuring chain")

	if s.iptablesCmd.ChainExists(version, TableFilter, chainName) {
		s.logger.Info().Str("chain", chainName).Str("version", string(version)).Msg("Flushing existing chain")
		if err := s.iptablesCmd.FlushChain(version, TableFilter, chainName); err != nil {
			return fmt.Errorf("failed to flush chain: %w", err)
		}
	} else {
		s.logger.Info().Str("chain", chainName).Str("version", string(version)).Msg("Creating chain")
		if err := s.iptablesCmd.CreateChain(version, TableFilter, chainName); err != nil {
			return fmt.Errorf("failed to create chain: %w", err)
		}
	}

	if linkToInput {
		if !s.iptablesCmd.RuleExists(version, TableFilter, string(ChainInput), []string{"-j", chainName}) {
			s.logger.Info().Str("version", string(version)).Msg("Linking chain to INPUT")
			if err := s.iptablesCmd.LinkChainToInput(version, chainName, 1); err != nil {
				return fmt.Errorf("failed to link chain to INPUT: %w", err)
			}
		}
	}

	establishedRule := NewRuleBuilder().
		MatchConntrack("ESTABLISHED", "RELATED").
		Jump(TargetReturn).
		Build()
	if !s.iptablesCmd.RuleExists(version, TableFilter, chainName, establishedRule) {
		s.logger.Info().Str("version", string(version)).Msg("Adding ESTABLISHED/RELATED return rule")
		if err := s.iptablesCmd.InsertRule(version, TableFilter, chainName, 1, establishedRule); err != nil {
			return fmt.Errorf("failed to add ESTABLISHED rule: %w", err)
		}
	}

	if s.enableLogging {
		logRule := NewRuleBuilder().
			MatchSet(ipsetName, "src").
			MatchLimit("10/min", "5").
			Jump(TargetLog).
			LogPrefix("ANTISCAN-v4: ").
			LogLevel("4").
			Build()
		if !s.iptablesCmd.RuleExists(version, TableFilter, chainName, logRule) {
			s.logger.Info().Str("version", string(version)).Msg("Adding LOG rule")
			if err := s.iptablesCmd.InsertRule(version, TableFilter, chainName, 2, logRule); err != nil {
				return fmt.Errorf("failed to add LOG rule: %w", err)
			}
		}
	}

	dropRule := NewRuleBuilder().MatchSet(ipsetName, "src").Jump(TargetDrop).Build()
	if !s.iptablesCmd.RuleExists(version, TableFilter, chainName, dropRule) {
		s.logger.Info().Str("version", string(version)).Msg("Adding DROP rule")
		if err := s.iptablesCmd.AppendRule(version, TableFilter, chainName, dropRule); err != nil {
			return fmt.Errorf("failed to add DROP rule: %w", err)
		}
	}

	return nil
}

// IsActive returns true if the SCANNERS-BLOCK chain exists and is linked to INPUT.
func (s *IptablesService) IsActive() bool {
	if !s.iptablesCmd.ChainExists(IPv4, TableFilter, chainName) {
		return false
	}
	return s.iptablesCmd.RuleExists(IPv4, TableFilter, string(ChainInput), []string{"-j", chainName})
}

// Save saves iptables rules. On Debian-based systems netfilter-persistent is
// used. On other systems iptables-save is called directly (rules will not
// survive a reboot without additional configuration such as an iptables systemd
// service, which is outside the scope of this tool).
func (s *IptablesService) Save() error {
	s.logger.Info().Msg("Saving iptables rules")

	if s.cmdSvc.CommandExists("netfilter-persistent") {
		return s.saveWithNetfilterPersistent()
	}

	// Non-Debian fallback: persist via iptables-save only.
	s.logger.Warn().Msg("netfilter-persistent not found; saving rules with iptables-save only (rules may not survive reboot)")
	if err := os.MkdirAll("/etc/iptables", 0755); err != nil {
		return fmt.Errorf("failed to create /etc/iptables: %w", err)
	}
	if err := s.iptablesCmd.Save(IPv4, IptablesRulesV4Path); err != nil {
		return fmt.Errorf("failed to save iptables rules: %w", err)
	}
	s.logger.Info().Str("path", IptablesRulesV4Path).Msg("iptables rules saved")
	return nil
}

// saveWithNetfilterPersistent saves using netfilter-persistent
func (s *IptablesService) saveWithNetfilterPersistent() error {
	if err := os.MkdirAll("/etc/iptables", 0755); err != nil {
		return fmt.Errorf("failed to create /etc/iptables: %w", err)
	}

	if err := s.iptablesCmd.Save(IPv4, "/etc/iptables/rules.v4"); err != nil {
		return fmt.Errorf("failed to save iptables: %w", err)
	}
	s.logger.Info().Msg("iptables rules saved to /etc/iptables/rules.v4")

	if err := s.cmdSvc.Run("netfilter-persistent", "save"); err != nil {
		s.logger.Warn().Err(err).Msg("netfilter-persistent save failed")
	}

	return nil
}
