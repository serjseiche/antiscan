package service

import (
	"fmt"
	"os"
	"os/user"
	"strconv"
	"strings"

	"github.com/rs/zerolog"
)

// logFileOwner is the user/group that should own antiscan log files.
type logFileOwner struct {
	user, group string
	uid, gid    int
}

// resolveLogFileOwner picks the user/group that should own antiscan log files.
// Debian's rsyslog runs as syslog:adm; other distros lack the syslog user and
// run rsyslog as root.
func resolveLogFileOwner() logFileOwner {
	owner := logFileOwner{user: "root", group: "root"}
	if u, err := user.Lookup("syslog"); err == nil {
		if uid, e := strconv.Atoi(u.Uid); e == nil {
			owner.user, owner.uid = "syslog", uid
		}
	}
	if g, err := user.LookupGroup("adm"); err == nil {
		if gid, e := strconv.Atoi(g.Gid); e == nil {
			owner.group, owner.gid = "adm", gid
		}
	}
	return owner
}

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

	if err := s.createLogFiles(); err != nil {
		return fmt.Errorf("failed to create log files: %w", err)
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
		return err
	}
	s.logger.Info().Str("path", RsyslogConfigPath).Msg("rsyslog config created")
	return nil
}

func (s *LoggingService) createLogFiles() error {
	owner := resolveLogFileOwner()

	for _, logFile := range []string{IPv4LogPath} {
		if _, err := os.Stat(logFile); !os.IsNotExist(err) {
			continue
		}

		f, err := os.Create(logFile)
		if err != nil {
			return fmt.Errorf("failed to create %s: %w", logFile, err)
		}
		f.Close()

		if err := os.Chown(logFile, owner.uid, owner.gid); err != nil {
			s.logger.Warn().Err(err).Str("file", logFile).Msg("Failed to chown log file")
		}
		if err := os.Chmod(logFile, 0640); err != nil {
			s.logger.Warn().Err(err).Str("file", logFile).Msg("Failed to chmod log file")
		}

		s.logger.Info().
			Str("file", logFile).
			Str("owner", owner.user+":"+owner.group).
			Msg("Log file created")
	}

	return nil
}

func (s *LoggingService) setupLogrotate() error {
	owner := resolveLogFileOwner()
	content := strings.ReplaceAll(LogrotateConfigTemplate, "{log_owner}", owner.user+" "+owner.group)
	if err := os.WriteFile(LogrotateConfigPath, []byte(content), 0644); err != nil {
		return err
	}
	s.logger.Info().Str("path", LogrotateConfigPath).Msg("logrotate config created")
	return nil
}

func (s *LoggingService) setupAggregationScript() error {
	owner := resolveLogFileOwner()
	content := strings.ReplaceAll(AggregateLogsScriptTemplate, "{log_owner}", owner.user+":"+owner.group)
	if err := os.WriteFile(AggregateLogsScriptPath, []byte(content), 0755); err != nil {
		return fmt.Errorf("failed to write aggregation script: %w", err)
	}

	s.logger.Info().Str("path", AggregateLogsScriptPath).Msg("Aggregation script created")
	return nil
}

// setupAggregationTimer creates a systemd service+timer that runs the aggregation script every 30 seconds.
func (s *LoggingService) setupAggregationTimer() error {
	if err := os.WriteFile(AggregateLogsServicePath, []byte(AggregateLogsServiceTemplate), 0644); err != nil {
		return err
	}
	s.logger.Info().Str("path", AggregateLogsServicePath).Msg("Aggregation systemd service created")

	if err := os.WriteFile(AggregateLogsTimerPath, []byte(AggregateLogsTimerTemplate), 0644); err != nil {
		return err
	}
	s.logger.Info().Str("path", AggregateLogsTimerPath).Msg("Aggregation systemd timer created")

	if err := s.cmdSvc.DaemonReload(); err != nil {
		s.logger.Warn().Err(err).Msg("daemon-reload failed")
	}

	if err := s.cmdSvc.Run("systemctl", "enable", "antiscan-aggregate.timer"); err != nil {
		s.logger.Warn().Err(err).Msg("Failed to enable antiscan-aggregate.timer")
	}

	if err := s.cmdSvc.Run("systemctl", "start", "antiscan-aggregate.timer"); err != nil {
		s.logger.Warn().Err(err).Msg("Failed to start antiscan-aggregate.timer")
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
