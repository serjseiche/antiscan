package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/serjseiche/antiscan/internal/logger"
	"github.com/serjseiche/antiscan/internal/service"
	"github.com/serjseiche/antiscan/internal/state"
)

var (
	urls           []string
	enableLogging  bool
	confirmYes     bool
	removeLogs     bool
	logLevel       string
	autoUpdate     bool
	updateInterval string
	version        = "dev" // set at build time via -ldflags
)

func main() {
	// Set a default logger so any output before PersistentPreRun is not lost.
	logger.SetGlobalLogger(logger.New())

	rootCmd := &cobra.Command{
		Use:     "antiscan-simple",
		Short:   "Manage scanner blocking via iptables and ipset",
		Long:    `Download subnet blocklists and configure iptables/ipset rules to block port scanners.`,
		Version: version,
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			logger.SetGlobalLogger(logger.NewWithLevel(logLevel))
		},
	}

	rootCmd.PersistentFlags().StringVar(&logLevel, "log-level", "info", "Log level (debug, info, warn, error)")

	fullCmd := &cobra.Command{
		Use:   "full",
		Short: "Run full setup (download, configure and apply)",
		Long:  `Downloads subnet lists, configures ipset and iptables, and saves rules for boot persistence.`,
		Run:   runFull,
	}
	fullCmd.Flags().StringArrayVarP(&urls, "urls", "u", []string{}, "URL(s) of subnet blocklists (repeatable)")
	fullCmd.Flags().BoolVarP(&enableLogging, "enable-logging", "l", false, "Enable logging of blocked connections")
	fullCmd.Flags().BoolVar(&autoUpdate, "auto-update", false, "Enable automatic blocklist updates")
	fullCmd.Flags().StringVar(&updateInterval, "update-interval", "24h", "Update interval (e.g. 24h, 30m, 7d)")
	fullCmd.MarkFlagRequired("urls")

	uninstallCmd := &cobra.Command{
		Use:   "uninstall",
		Short: "Remove all changes made by antiscan-simple",
		Long:  `Removes iptables/ipset chains, systemd services and config files created by antiscan-simple.`,
		Run:   runUninstall,
	}
	uninstallCmd.Flags().BoolVar(&confirmYes, "yes", false, "Confirm removal without interactive prompt")
	uninstallCmd.Flags().BoolVar(&removeLogs, "remove-logs", false, "Also delete antiscan-simple log files from /var/log")

	statusCmd := &cobra.Command{
		Use:   "status",
		Short: "Show current protection status",
		Run:   runStatus,
	}

	updateCmd := &cobra.Command{
		Use:   "update",
		Short: "Update blocklists from saved URLs",
		Run:   runUpdate,
	}

	rootCmd.AddCommand(fullCmd)
	rootCmd.AddCommand(uninstallCmd)
	rootCmd.AddCommand(statusCmd)
	rootCmd.AddCommand(updateCmd)

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func runFull(cmd *cobra.Command, args []string) {
	log := logger.Global()
	log.Info().Msg("=== Full setup ===")

	cmdSvc := service.NewCommandService(log.Logger)
	installer := service.NewInstallerService(log.Logger)
	downloader := service.NewDownloader(log.Logger)
	ipsetSvc := service.NewIpsetService(log.Logger, cmdSvc)
	iptablesSvc := service.NewIptablesService(log.Logger, cmdSvc, enableLogging)
	loggingSvc := service.NewLoggingService(log.Logger, cmdSvc)

	if err := installer.CheckRootPrivileges(); err != nil {
		log.Fatal().Err(err).Msg("Insufficient privileges")
	}

	if err := installer.CheckNoUFW(); err != nil {
		log.Fatal().Err(err).Msg("Incompatible configuration")
	}

	if err := installer.EnsureDependencies(); err != nil {
		log.Fatal().Err(err).Msg("Dependency check failed")
	}

	if err := installer.EnsureNetfilterPersistent(); err != nil {
		log.Fatal().Err(err).Msg("netfilter-persistent check failed")
	}

	if enableLogging {
		if err := installer.EnsureLoggingDependencies(); err != nil {
			log.Fatal().Err(err).Msg("Logging dependency check failed")
		}
	}

	networks, err := downloader.Download(urls)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to download subnets")
	}

	if err := ipsetSvc.Setup(); err != nil {
		log.Fatal().Err(err).Msg("Failed to setup ipset")
	}

	if err := ipsetSvc.Fill(networks); err != nil {
		log.Fatal().Err(err).Msg("Failed to fill ipset")
	}

	if err := iptablesSvc.SetupChain(); err != nil {
		log.Fatal().Err(err).Msg("Failed to setup iptables")
	}

	if enableLogging {
		if err := loggingSvc.Setup(); err != nil {
			log.Warn().Err(err).Msg("Failed to setup logging configuration")
		}
	}

	if err := ipsetSvc.Save("/etc/ipset.conf"); err != nil {
		log.Warn().Err(err).Msg("Failed to save ipset configuration")
	}

	if err := ipsetSvc.CreateRestoreService(); err != nil {
		log.Warn().Err(err).Msg("Failed to create ipset restore service")
	}

	if err := iptablesSvc.Save(); err != nil {
		log.Fatal().Err(err).Msg("Failed to save iptables rules — setup aborted")
	}

	cfg := &state.Config{
		URLs:           urls,
		EnableLogging:  enableLogging,
		AutoUpdate:     autoUpdate,
		UpdateInterval: updateInterval,
		LastUpdate:     time.Now(),
	}
	if err := state.Save(cfg); err != nil {
		log.Warn().Err(err).Msg("Failed to save state file")
	} else {
		log.Info().Str("path", state.Path()).Msg("State saved")
	}

	if autoUpdate {
		updaterSvc := service.NewUpdaterService(log.Logger, cmdSvc)
		if err := updaterSvc.Setup(updateInterval); err != nil {
			log.Warn().Err(err).Msg("Failed to configure auto-update")
		}
	}

	log.Info().Msg("Full setup completed successfully")
}

func runUpdate(cmd *cobra.Command, args []string) {
	log := logger.Global()
	log.Info().Msg("=== Updating blocklists ===")

	installer := service.NewInstallerService(log.Logger)
	if err := installer.CheckRootPrivileges(); err != nil {
		log.Fatal().Err(err).Msg("Must be run as root (use sudo)")
	}

	cfg, err := state.Load()
	if err != nil {
		log.Fatal().Err(err).Msg("Not configured — run antiscan-simple full first")
	}

	cmdSvc := service.NewCommandService(log.Logger)
	downloader := service.NewDownloader(log.Logger)
	ipsetSvc := service.NewIpsetService(log.Logger, cmdSvc)
	iptablesSvc := service.NewIptablesService(log.Logger, cmdSvc, cfg.EnableLogging)

	networks, err := downloader.Download(cfg.URLs)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to download blocklists")
	}
	if networks.TotalCount() == 0 {
		log.Fatal().Msg("Downloaded list is empty, update aborted")
	}

	if err := ipsetSvc.Setup(); err != nil {
		log.Fatal().Err(err).Msg("Failed to reset ipset")
	}
	if err := ipsetSvc.Fill(networks); err != nil {
		log.Fatal().Err(err).Msg("Failed to fill ipset")
	}
	if err := ipsetSvc.Save("/etc/ipset.conf"); err != nil {
		log.Warn().Err(err).Msg("Failed to save ipset configuration")
	}

	if err := iptablesSvc.SetupChain(); err != nil {
		log.Fatal().Err(err).Msg("Failed to configure iptables chains")
	}

	cfg.LastUpdate = time.Now()
	if err := state.Save(cfg); err != nil {
		log.Warn().Err(err).Msg("Failed to update state file")
	}

	log.Info().
		Int("total", networks.TotalCount()).
		Msg("Blocklists updated successfully")
}

func runStatus(cmd *cobra.Command, args []string) {
	log := logger.Global()

	installer := service.NewInstallerService(log.Logger)
	if err := installer.CheckRootPrivileges(); err != nil {
		log.Fatal().Err(err).Msg("Must be run as root (use sudo)")
	}

	cmdSvc := service.NewCommandService(log.Logger)
	statusSvc := service.NewStatusService(log.Logger, cmdSvc)

	if err := statusSvc.Render(os.Stdout); err != nil {
		log.Fatal().Err(err).Msg("Failed to get status")
	}
}

func runUninstall(cmd *cobra.Command, args []string) {
	log := logger.Global()
	log.Info().Msg("=== Uninstalling antiscan-simple ===")

	cmdSvc := service.NewCommandService(log.Logger)
	installer := service.NewInstallerService(log.Logger)
	uninstaller := service.NewUninstallerService(log.Logger, cmdSvc)

	if err := installer.CheckRootPrivileges(); err != nil {
		log.Fatal().Err(err).Msg("Must be run as root (use sudo)")
	}

	if !confirmYes {
		fmt.Print("This will remove antiscan-simple rules, systemd services and configuration. Continue? [y/N]: ")
		if !confirmFromStdin() {
			log.Info().Msg("Uninstall cancelled by user")
			return
		}
	}

	if err := uninstaller.Uninstall(removeLogs); err != nil {
		log.Fatal().Err(err).Msg("Uninstall failed")
	}

	if removeLogs {
		log.Info().Msg("Uninstall complete, logs removed")
		return
	}

	log.Info().Msg("Uninstall complete, logs preserved")
}

func confirmFromStdin() bool {
	reader := bufio.NewReader(os.Stdin)
	response, err := reader.ReadString('\n')
	if err != nil {
		return false
	}

	response = strings.TrimSpace(strings.ToLower(response))
	return response == "y" || response == "yes"
}
