package service

import (
	"fmt"
	"os"

	"github.com/serj1974-maker/antiscan/internal/domain"

	"github.com/rs/zerolog"
)

const (
	ipsetV4Name = "SCANNERS-BLOCK-V4"
)

// IpsetService handles ipset operations
type IpsetService struct {
	logger   zerolog.Logger
	cmdSvc   *CommandService
	ipsetCmd *IpsetCommandService
}

// NewIpsetService creates a new ipset service
func NewIpsetService(logger zerolog.Logger, cmdSvc *CommandService) *IpsetService {
	return &IpsetService{
		logger:   logger,
		cmdSvc:   cmdSvc,
		ipsetCmd: NewIpsetCommandService(logger, cmdSvc),
	}
}

// Setup creates or flushes ipset sets
func (s *IpsetService) Setup() error {
	s.logger.Info().Msg("Setting up ipset")

	if err := s.setupSet(ipsetV4Name, "inet"); err != nil {
		return fmt.Errorf("failed to setup IPv4 set: %w", err)
	}

	s.logger.Info().Msg("ipset ready")
	return nil
}

// setupSet creates or flushes a single ipset set
func (s *IpsetService) setupSet(name, family string) error {
	s.logger.Debug().Str("set", name).Msg("Checking ipset")

	if s.ipsetCmd.Exists(name) {
		s.logger.Info().Str("set", name).Msg("Flushing existing set")
		if err := s.ipsetCmd.Flush(name); err != nil {
			return fmt.Errorf("failed to flush set %s: %w", name, err)
		}
		s.logger.Info().Str("set", name).Msg("Set flushed")
	} else {
		s.logger.Info().Str("set", name).Str("family", family).Msg("Creating set")
		if err := s.ipsetCmd.CreateHashNet(name, Family(family), 1024, 65536); err != nil {
			return fmt.Errorf("failed to create set %s: %w", name, err)
		}
		s.logger.Info().Str("set", name).Msg("Set created")
	}

	return nil
}

// Fill populates ipset sets with subnets
func (s *IpsetService) Fill(networks *domain.NetworkList) error {
	s.logger.Info().
		Int("ipv4_count", networks.IPv4Count()).
		Msg("Filling ipset")

	added, errors := s.fillSet(ipsetV4Name, networks.IPv4Subnets, "IPv4")

	s.logger.Info().
		Int("added", added).
		Int("errors", errors).
		Msg("ipset filled")

	if errors > 0 {
		return fmt.Errorf("failed to add %d subnet(s) to ipset", errors)
	}
	return nil
}

// fillSet adds subnets to a specific ipset set
func (s *IpsetService) fillSet(setName string, subnets []string, label string) (added, errors int) {
	total := len(subnets)
	s.logger.Info().Int("total", total).Str("type", label).Msg("Adding subnets to ipset")

	for i, subnet := range subnets {
		if err := s.ipsetCmd.Add(setName, subnet); err == nil {
			added++
			if (i+1)%100 == 0 {
				s.logger.Debug().
					Int("progress", i+1).
					Int("total", total).
					Str("type", label).
					Msg("Progress")
			}
		} else {
			errors++
			s.logger.Warn().
				Err(err).
				Str("subnet", subnet).
				Str("set", setName).
				Msg("Failed to add subnet")
		}
	}

	return added, errors
}

// Save saves ipset configuration to file
func (s *IpsetService) Save(path string) error {
	s.logger.Info().Str("path", path).Msg("Saving ipset configuration")

	if err := s.ipsetCmd.Save(path); err != nil {
		return fmt.Errorf("failed to save ipset: %w", err)
	}

	s.logger.Info().Str("path", path).Msg("ipset configuration saved")
	return nil
}

// CreateRestoreService creates systemd service to restore ipset on boot
func (s *IpsetService) CreateRestoreService() error {
	s.logger.Info().Msg("Creating systemd service to restore ipset on boot")

	if err := os.WriteFile(IpsetRestoreServicePath, []byte(IpsetRestoreServiceTemplate), 0644); err != nil {
		return fmt.Errorf("failed to create systemd service: %w", err)
	}
	s.logger.Info().Str("path", IpsetRestoreServicePath).Msg("Created systemd service")

	if err := s.cmdSvc.DaemonReload(); err != nil {
		s.logger.Warn().Err(err).Msg("daemon-reload failed")
	}

	if err := s.cmdSvc.EnableService("antiscan-ipset-restore.service"); err != nil {
		return fmt.Errorf("failed to enable service: %w", err)
	}
	s.logger.Info().Msg("ipset restore service enabled — ipset will be restored on boot")
	return nil
}
