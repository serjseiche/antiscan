package service

import (
	"fmt"
	"os"

	"github.com/rs/zerolog"
)

// LoggingService handles logging configuration setup
type LoggingService struct {
	logger zerolog.Logger
	cmdSvc *CommandService
}

// NewLoggingService creates a new logging service
func NewLoggingService(logger zerolog.Logger, cmdSvc *CommandService) *LoggingService {
	return &LoggingService{
		logger: logger,
		cmdSvc: cmdSvc,
	}
}

// Setup configures rsyslog, logrotate, and aggregation script
func (s *LoggingService) Setup() error {
	s.logger.Info().Msg("Configuring logging")

	if err := s.setupRsyslog(); err != nil {
		return fmt.Errorf("failed to setup rsyslog: %w", err)
	}

	if err := s.setupLogrotate(); err != nil {
		return fmt.Errorf("failed to setup logrotate: %w", err)
	}

	if err := s.setupAggregationScript(); err != nil {
		return fmt.Errorf("failed to setup aggregation script: %w", err)
	}

	if err := s.setupAggregationTimer(); err != nil {
		return fmt.Errorf("failed to setup aggregation timer: %w", err)
	}

	if err := s.restartRsyslog(); err != nil {
		s.logger.Warn().Err(err).Msg("Failed to restart rsyslog — may require manual restart")
	}

	s.logger.Info().Msg("Logging configured")
	s.logger.Info().Msg("  Raw logs:        /var/log/iptables-scanners-ipv4.log")
	s.logger.Info().Msg("  Aggregated CSV:  /var/log/iptables-scanners-aggregate.csv (updated every 30s)")
	s.logger.Info().Msg("  Rate limit:      10 entries/minute")
	s.logger.Info().Msg("  Timer status:    systemctl status antiscan-aggregate.timer")

	return nil
}

func (s *LoggingService) setupRsyslog() error {
	if err := os.WriteFile(RsyslogConfigPath, []byte(RsyslogConfigTemplate), 0644); err != nil {
		return fmt.Errorf("write %s: %w", RsyslogConfigPath, err)
	}
	s.logger.Info().Str("path", RsyslogConfigPath).Msg("rsyslog config created")
	return nil
}

func (s *LoggingService) setupLogrotate() error {
	if err := os.WriteFile(LogrotateConfigPath, []byte(LogrotateConfigTemplate), 0644); err != nil {
		return fmt.Errorf("write %s: %w", LogrotateConfigPath, err)
	}
	s.logger.Info().Str("path", LogrotateConfigPath).Msg("logrotate config created")
	return nil
}

func (s *LoggingService) setupAggregationScript() error {
	// 0755 already sets the execute bit; no separate chmod needed.
	if err := os.WriteFile(AggregateLogsScriptPath, []byte(AggregateLogsScriptTemplate), 0755); err != nil {
		return fmt.Errorf("failed to write aggregation script: %w", err)
	}

	s.logger.Info().Str("path", AggregateLogsScriptPath).Msg("Aggregation script created")
	return nil
}

// setupAggregationTimer creates a systemd service+timer that runs the aggregation script every 30 seconds.
func (s *LoggingService) setupAggregationTimer() error {
	if err := os.WriteFile(AggregateLogsServicePath, []byte(AggregateLogsServiceTemplate), 0644); err != nil {
		return fmt.Errorf("write %s: %w", AggregateLogsServicePath, err)
	}
	s.logger.Info().Str("path", AggregateLogsServicePath).Msg("Aggregation systemd service created")

	if err := os.WriteFile(AggregateLogsTimerPath, []byte(AggregateLogsTimerTemplate), 0644); err != nil {
		return fmt.Errorf("write %s: %w", AggregateLogsTimerPath, err)
	}
	s.logger.Info().Str("path", AggregateLogsTimerPath).Msg("Aggregation systemd timer created")

	if err := s.cmdSvc.DaemonReload(); err != nil {
		s.logger.Warn().Err(err).Msg("daemon-reload failed")
	}

	if err := s.cmdSvc.Run("systemctl", "enable", "--now", "antiscan-aggregate.timer"); err != nil {
		return fmt.Errorf("failed to enable aggregation timer: %w", err)
	}

	s.logger.Info().Msg("Aggregation timer enabled (runs every 30 seconds)")
	return nil
}

func (s *LoggingService) restartRsyslog() error {
	if err := s.cmdSvc.RestartService("rsyslog"); err != nil {
		return err
	}
	s.logger.Info().Msg("rsyslog restarted")
	return nil
}
