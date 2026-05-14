package service

import (
	"fmt"
	"os"

	"github.com/rs/zerolog"
)

const (
	chainName       = "SCANNERS-BLOCK"
	dockerUserChain = "DOCKER-USER"
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

// SetupChain creates and configures the SCANNERS-BLOCK chain
func (s *IptablesService) SetupChain() error {
	s.logger.Info().Msg("Setting up iptables chains")

	if err := s.setupScannersBlockChain(ipsetV4Name); err != nil {
		return fmt.Errorf("failed to setup SCANNERS-BLOCK chain: %w", err)
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
	if !s.iptablesCmd.ChainExists(TableFilter, dockerUserChain) {
		s.logger.Info().Msg("Creating DOCKER-USER chain")
		if err := s.iptablesCmd.CreateChain(TableFilter, dockerUserChain); err != nil {
			return fmt.Errorf("failed to create DOCKER-USER: %w", err)
		}
		// Add RETURN at the end so Docker behaviour is preserved if it appears later
		if err := s.iptablesCmd.AppendRule(TableFilter, dockerUserChain, []string{"-j", "RETURN"}); err != nil {
			s.logger.Warn().Err(err).Msg("Failed to add RETURN to DOCKER-USER")
		}
		justCreated = true
	}

	dropRule := []string{"-m", "set", "--match-set", ipsetV4Name, "src", "-j", "DROP"}
	if !s.iptablesCmd.RuleExists(TableFilter, dockerUserChain, dropRule) {
		s.logger.Info().Msg("Inserting DROP rule into DOCKER-USER at position 1")
		if err := s.iptablesCmd.InsertRule(TableFilter, dockerUserChain, 1, dropRule); err != nil {
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

// setupScannersBlockChain configures the SCANNERS-BLOCK chain and links it to INPUT.
func (s *IptablesService) setupScannersBlockChain(ipsetName string) error {
	if s.iptablesCmd.ChainExists(TableFilter, chainName) {
		s.logger.Info().Str("chain", chainName).Msg("Flushing existing chain")
		if err := s.iptablesCmd.FlushChain(TableFilter, chainName); err != nil {
			return fmt.Errorf("failed to flush chain: %w", err)
		}
	} else {
		s.logger.Info().Str("chain", chainName).Msg("Creating chain")
		if err := s.iptablesCmd.CreateChain(TableFilter, chainName); err != nil {
			return fmt.Errorf("failed to create chain: %w", err)
		}
	}

	if !s.iptablesCmd.RuleExists(TableFilter, string(ChainInput), []string{"-j", chainName}) {
		s.logger.Info().Msg("Linking chain to INPUT")
		if err := s.iptablesCmd.LinkChainToInput(chainName, 1); err != nil {
			return fmt.Errorf("failed to link chain to INPUT: %w", err)
		}
	}

	establishedRule := NewRuleBuilder().
		MatchConntrack("ESTABLISHED", "RELATED").
		Jump(TargetReturn).
		Build()
	if !s.iptablesCmd.RuleExists(TableFilter, chainName, establishedRule) {
		s.logger.Info().Msg("Adding ESTABLISHED/RELATED return rule")
		if err := s.iptablesCmd.InsertRule(TableFilter, chainName, 1, establishedRule); err != nil {
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
		if !s.iptablesCmd.RuleExists(TableFilter, chainName, logRule) {
			s.logger.Info().Msg("Adding LOG rule")
			if err := s.iptablesCmd.InsertRule(TableFilter, chainName, 2, logRule); err != nil {
				return fmt.Errorf("failed to add LOG rule: %w", err)
			}
		}
	}

	dropRule := NewRuleBuilder().MatchSet(ipsetName, "src").Jump(TargetDrop).Build()
	if !s.iptablesCmd.RuleExists(TableFilter, chainName, dropRule) {
		s.logger.Info().Msg("Adding DROP rule")
		if err := s.iptablesCmd.AppendRule(TableFilter, chainName, dropRule); err != nil {
			return fmt.Errorf("failed to add DROP rule: %w", err)
		}
	}

	return nil
}

// IsActive returns true if the SCANNERS-BLOCK chain exists and is linked to INPUT.
func (s *IptablesService) IsActive() bool {
	if !s.iptablesCmd.ChainExists(TableFilter, chainName) {
		return false
	}
	return s.iptablesCmd.RuleExists(TableFilter, string(ChainInput), []string{"-j", chainName})
}

// Save saves iptables rules using netfilter-persistent
func (s *IptablesService) Save() error {
	s.logger.Info().Msg("Saving iptables rules")

	if !s.cmdSvc.CommandExists("netfilter-persistent") {
		return fmt.Errorf("netfilter-persistent is not installed, run dependency setup first")
	}

	return s.saveWithNetfilterPersistent()
}

// saveWithNetfilterPersistent saves using netfilter-persistent
func (s *IptablesService) saveWithNetfilterPersistent() error {
	if err := os.MkdirAll("/etc/iptables", 0755); err != nil {
		return fmt.Errorf("failed to create /etc/iptables: %w", err)
	}

	if err := s.iptablesCmd.Save(IptablesRulesV4Path); err != nil {
		return fmt.Errorf("failed to save iptables: %w", err)
	}
	s.logger.Info().Str("path", IptablesRulesV4Path).Msg("iptables rules saved")

	if err := s.cmdSvc.Run("netfilter-persistent", "save"); err != nil {
		s.logger.Warn().Err(err).Msg("netfilter-persistent save failed")
	}

	return nil
}
