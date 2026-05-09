package service

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/rs/zerolog"
)

// UpdaterService manages the antiscan-simple-update systemd timer.
type UpdaterService struct {
	logger zerolog.Logger
	cmdSvc *CommandService
}

// NewUpdaterService creates a new updater service.
func NewUpdaterService(logger zerolog.Logger, cmdSvc *CommandService) *UpdaterService {
	return &UpdaterService{
		logger: logger,
		cmdSvc: cmdSvc,
	}
}

// Setup writes the update systemd service+timer and enables them.
func (s *UpdaterService) Setup(interval string) error {
	d, err := ParseInterval(interval)
	if err != nil {
		return fmt.Errorf("неверный интервал %q: %w", interval, err)
	}

	systemdInterval := FormatDurationForSystemd(d)

	svcContent := UpdateServiceTemplate
	timerContent := strings.ReplaceAll(UpdateTimerTemplate, "{interval}", systemdInterval)

	if err := os.WriteFile(UpdateServicePath, []byte(svcContent), 0644); err != nil {
		return fmt.Errorf("не удалось записать %s: %w", UpdateServicePath, err)
	}
	s.logger.Info().Str("path", UpdateServicePath).Msg("Создан systemd сервис обновления")

	if err := os.WriteFile(UpdateTimerPath, []byte(timerContent), 0644); err != nil {
		return fmt.Errorf("не удалось записать %s: %w", UpdateTimerPath, err)
	}
	s.logger.Info().Str("path", UpdateTimerPath).Msg("Создан systemd таймер обновления")

	if err := s.cmdSvc.DaemonReload(); err != nil {
		s.logger.Warn().Err(err).Msg("daemon-reload завершился с ошибкой")
	}

	if err := s.cmdSvc.Run("systemctl", "enable", "--now", "antiscan-simple-update.timer"); err != nil {
		return fmt.Errorf("не удалось включить таймер обновления: %w", err)
	}
	s.logger.Info().Str("interval", systemdInterval).Msg("Таймер автообновления включён")
	return nil
}

// ParseInterval parses a duration string supporting d/h/m/s suffixes.
// Additionally accepts "<N>d" for days (not supported by time.ParseDuration).
func ParseInterval(s string) (time.Duration, error) {
	if strings.HasSuffix(s, "d") {
		days, err := strconv.Atoi(strings.TrimSuffix(s, "d"))
		if err != nil || days <= 0 {
			return 0, fmt.Errorf("ожидается формат вида 7d, 24h, 30m")
		}
		return time.Duration(days) * 24 * time.Hour, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("ожидается формат вида 7d, 24h, 30m: %w", err)
	}
	if d <= 0 {
		return 0, fmt.Errorf("интервал должен быть положительным")
	}
	return d, nil
}

// FormatDurationForSystemd converts a duration to a systemd-compatible string.
func FormatDurationForSystemd(d time.Duration) string {
	if d%time.Hour == 0 {
		return fmt.Sprintf("%dh", int(d.Hours()))
	}
	if d%time.Minute == 0 {
		return fmt.Sprintf("%dmin", int(d.Minutes()))
	}
	return fmt.Sprintf("%ds", int(d.Seconds()))
}
