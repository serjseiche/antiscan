package service

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/rs/zerolog"
)

// InstallerService handles dependency checks
type InstallerService struct {
	logger zerolog.Logger
}

// NewInstallerService creates a new installer service
func NewInstallerService(logger zerolog.Logger) *InstallerService {
	return &InstallerService{
		logger: logger,
	}
}

// EnsureDependencies checks that required packages are installed
func (s *InstallerService) EnsureDependencies() error {
	s.logger.Info().Msg("Проверка зависимостей")

	for _, pkg := range []string{"iptables", "ipset"} {
		if !s.commandExists(pkg) {
			return fmt.Errorf(
				"%s не установлен.\nУстановите вручную:\n  Debian/Ubuntu: sudo apt-get install %s\n  RHEL/CentOS:   sudo yum install %s",
				pkg, pkg, pkg,
			)
		}
		s.logger.Debug().Msgf("%s уже установлен", pkg)
	}

	s.logger.Info().Msg("Все зависимости удовлетворены")
	return nil
}

// CheckNoUFW returns an error if UFW is detected. antiscan-simple requires direct iptables access.
func (s *InstallerService) CheckNoUFW() error {
	if s.commandExists("ufw") {
		return fmt.Errorf(
			"UFW обнаружен в системе. antiscan-simple работает только с iptables напрямую.\n" +
				"Удалите UFW перед установкой:\n" +
				"  Debian/Ubuntu: sudo apt remove --purge ufw\n" +
				"  RHEL/CentOS:   sudo yum remove ufw",
		)
	}
	return nil
}

// EnsureNetfilterPersistent checks that netfilter-persistent is installed (Debian only)
func (s *InstallerService) EnsureNetfilterPersistent() error {
	s.logger.Info().Msg("Проверка системы сохранения правил")

	distro := getDistroType()

	if distro != "debian" {
		s.logger.Debug().Msg("netfilter-persistent доступен только для Debian-based систем")
		return nil
	}

	if s.commandExists("netfilter-persistent") {
		s.logger.Debug().Msg("netfilter-persistent уже установлен")
		return nil
	}

	return fmt.Errorf(
		"netfilter-persistent не установлен.\nУстановите вручную:\n  Debian/Ubuntu: sudo apt-get install netfilter-persistent iptables-persistent",
	)
}

// commandExists checks if a command is available in PATH
func (s *InstallerService) commandExists(cmd string) bool {
	_, err := exec.LookPath(cmd)
	return err == nil
}

// getDistroType detects the Linux distribution type
func getDistroType() string {
	if _, err := os.Stat("/etc/debian_version"); err == nil {
		return "debian"
	}
	if _, err := os.Stat("/etc/redhat-release"); err == nil {
		return "redhat"
	}
	return "unknown"
}

// CheckRootPrivileges verifies the program is running as root
func (s *InstallerService) CheckRootPrivileges() error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("программа должна быть запущена от root (используйте sudo)")
	}
	return nil
}
