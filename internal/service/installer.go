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
	s.logger.Info().Msg("Checking dependencies")

	for _, pkg := range []string{"iptables", "ipset"} {
		if !s.commandExists(pkg) {
			return fmt.Errorf(
				"%s is not installed.\nInstall manually:\n  Debian/Ubuntu: sudo apt-get install %s\n  RHEL/CentOS:   sudo yum install %s",
				pkg, pkg, pkg,
			)
		}
		s.logger.Debug().Str("pkg", pkg).Msg("Dependency installed")
	}

	s.logger.Info().Msg("All dependencies satisfied")
	return nil
}

// CheckNoUFW returns an error if UFW is detected. antiscan-simple requires direct iptables access.
func (s *InstallerService) CheckNoUFW() error {
	if s.commandExists("ufw") {
		return fmt.Errorf(
			"UFW detected. antiscan-simple requires direct iptables access.\n" +
				"Remove UFW before installing:\n" +
				"  Debian/Ubuntu: sudo apt remove --purge ufw\n" +
				"  RHEL/CentOS:   sudo yum remove ufw",
		)
	}
	return nil
}

// EnsureNetfilterPersistent checks that netfilter-persistent is installed (Debian only)
func (s *InstallerService) EnsureNetfilterPersistent() error {
	s.logger.Info().Msg("Checking rule persistence tool")

	distro := getDistroType()

	if distro != "debian" {
		s.logger.Debug().Msg("netfilter-persistent is only available on Debian-based systems")
		return nil
	}

	if s.commandExists("netfilter-persistent") {
		s.logger.Debug().Msg("netfilter-persistent is installed")
		return nil
	}

	return fmt.Errorf(
		"netfilter-persistent is not installed.\nInstall manually:\n  Debian/Ubuntu: sudo apt-get install netfilter-persistent iptables-persistent",
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

// EnsureLoggingDependencies checks binaries required when --enable-logging is set.
func (s *InstallerService) EnsureLoggingDependencies() error {
	s.logger.Info().Msg("Checking logging dependencies")

	if !s.commandExists("whois") {
		return fmt.Errorf(
			"whois is not installed (required for log aggregation).\n" +
				"Install manually:\n" +
				"  Debian/Ubuntu: sudo apt-get install whois\n" +
				"  RHEL/CentOS:   sudo yum install whois",
		)
	}
	s.logger.Debug().Str("pkg", "whois").Msg("Dependency installed")

	if !s.commandExists("rsyslog") && !s.commandExists("rsyslogd") {
		return fmt.Errorf(
			"rsyslog is not installed (required for iptables log capture).\n" +
				"Install manually:\n" +
				"  Debian/Ubuntu: sudo apt-get install rsyslog\n" +
				"  RHEL/CentOS:   sudo yum install rsyslog",
		)
	}
	s.logger.Debug().Str("pkg", "rsyslog").Msg("Dependency installed")

	s.logger.Info().Msg("All logging dependencies satisfied")
	return nil
}

// CheckRootPrivileges verifies the program is running as root
func (s *InstallerService) CheckRootPrivileges() error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("must be run as root (use sudo)")
	}
	return nil
}
