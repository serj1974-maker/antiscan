package service

import (
	"fmt"
	"os"

	"github.com/rs/zerolog"
)

// InstallerService handles dependency checks
type InstallerService struct {
	logger  zerolog.Logger
	cmdSvc  *CommandService
}

// NewInstallerService creates a new installer service
func NewInstallerService(logger zerolog.Logger, cmdSvc *CommandService) *InstallerService {
	return &InstallerService{
		logger: logger,
		cmdSvc: cmdSvc,
	}
}

// EnsureDependencies checks that required packages are installed
func (s *InstallerService) EnsureDependencies() error {
	s.logger.Info().Msg("Checking dependencies")

	for _, pkg := range []string{"iptables", "ipset"} {
		if !s.cmdSvc.CommandExists(pkg) {
			return fmt.Errorf(
				"%s is not installed.\nInstall manually:\n  Debian/Ubuntu: sudo apt-get install %s\n  RHEL/CentOS:   sudo yum install %s",
				pkg, pkg, pkg,
			)
		}
		s.logger.Debug().Msgf("%s is installed", pkg)
	}

	s.logger.Info().Msg("All dependencies satisfied")
	return nil
}

// CheckNoUFW returns an error if the ufw binary is present.
// Intentionally checks binary presence rather than service-active state: even an
// inactive UFW installation can re-activate on reboot or package update and conflict
// with direct iptables management. Removing the package is the only safe option.
func (s *InstallerService) CheckNoUFW() error {
	if s.cmdSvc.CommandExists("ufw") {
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

	if s.cmdSvc.CommandExists("netfilter-persistent") {
		s.logger.Debug().Msg("netfilter-persistent is installed")
		return nil
	}

	return fmt.Errorf(
		"netfilter-persistent is not installed.\nInstall manually:\n  Debian/Ubuntu: sudo apt-get install netfilter-persistent iptables-persistent",
	)
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

	if !s.cmdSvc.CommandExists("whois") {
		return fmt.Errorf(
			"whois is not installed (required for log aggregation).\n" +
				"Install manually:\n" +
				"  Debian/Ubuntu: sudo apt-get install whois\n" +
				"  RHEL/CentOS:   sudo yum install whois",
		)
	}
	s.logger.Debug().Str("pkg", "whois").Msg("Dependency installed")

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
