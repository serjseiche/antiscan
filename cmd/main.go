package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/serj1974-maker/antiscan/internal/logger"
	"github.com/serj1974-maker/antiscan/internal/service"
	"github.com/serj1974-maker/antiscan/internal/state"
)

var (
	urls           []string
	enableLogging  bool
	confirmYes     bool
	removeLogs     bool
	logLevel       string
	autoUpdate     bool
	updateInterval string
	version        = "dev" // Версия будет устанавливаться при сборке через -ldflags
)

func main() {
	// Setup logger
	log := logger.New()
	logger.SetGlobalLogger(log)

	rootCmd := &cobra.Command{
		Use:     "traffic-guard",
		Short:   "Инструмент для управления блокировкой сканеров через iptables и ipset",
		Long:    `Утилита для скачивания списков подсетей сканеров и настройки правил iptables/ipset для их блокировки.`,
		Version: version,
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			// Update logger level if specified
			if logLevel != "" {
				log = logger.NewWithLevel(logLevel)
				logger.SetGlobalLogger(log)
			}
		},
	}

	rootCmd.PersistentFlags().StringVar(&logLevel, "log-level", "info", "Log level (debug, info, warn, error)")

	fullCmd := &cobra.Command{
		Use:   "full",
		Short: "Выполнить полную установку (скачать, настроить и применить)",
		Long:  `Скачивает списки подсетей, настраивает ipset и iptables, сохраняет правила для автозагрузки.`,
		Run:   runFull,
	}
	fullCmd.Flags().StringSliceVarP(&urls, "urls", "u", []string{}, "Список URL для скачивания подсетей")
	fullCmd.Flags().BoolVarP(&enableLogging, "enable-logging", "l", false, "Включить логирование заблокированных подключений")
	fullCmd.Flags().BoolVar(&autoUpdate, "auto-update", false, "Включить автоматическое обновление списков")
	fullCmd.Flags().StringVar(&updateInterval, "update-interval", "24h", "Интервал обновления (например: 24h, 30m, 7d)")
	fullCmd.MarkFlagRequired("urls")

	uninstallCmd := &cobra.Command{
		Use:   "uninstall",
		Short: "Удалить все изменения, внесённые traffic-guard",
		Long:  `Удаляет цепочки iptables/ipset, systemd сервисы и конфигурационные файлы, созданные traffic-guard.`,
		Run:   runUninstall,
	}
	uninstallCmd.Flags().BoolVar(&confirmYes, "yes", false, "Подтвердить удаление без интерактивного запроса")
	uninstallCmd.Flags().BoolVar(&removeLogs, "remove-logs", false, "Удалить логи traffic-guard из /var/log")

	statusCmd := &cobra.Command{
		Use:   "status",
		Short: "Показать текущее состояние защиты",
		Run:   runStatus,
	}

	updateCmd := &cobra.Command{
		Use:   "update",
		Short: "Обновить списки блокировки из сохранённых URL",
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
	log.Info().Msg("=== Полная установка ===")

	// Create services
	// Create command service
	cmdSvc := service.NewCommandService(log.Logger)

	installer := service.NewInstallerService(log.Logger)
	downloader := service.NewDownloader(log.Logger)
	ipsetSvc := service.NewIpsetService(log.Logger, cmdSvc)
	iptablesSvc := service.NewIptablesService(log.Logger, cmdSvc, enableLogging)
	loggingSvc := service.NewLoggingService(log.Logger, cmdSvc)

	// Check root
	if err := installer.CheckRootPrivileges(); err != nil {
		log.Fatal().Err(err).Msg("Недостаточно прав")
	}

	if err := installer.CheckNoUFW(); err != nil {
		log.Fatal().Err(err).Msg("Несовместимая конфигурация")
	}

	if len(urls) == 0 {
		log.Panic().Msg("Не указаны URL для скачивания подсетей. Используйте флаг --urls")
	}

	// Ensure dependencies
	if err := installer.EnsureDependencies(); err != nil {
		log.Fatal().Err(err).Msg("Failed to install dependencies")
	}

	// Ensure netfilter-persistent is installed
	if err := installer.EnsureNetfilterPersistent(); err != nil {
		log.Fatal().Err(err).Msg("Failed to install netfilter-persistent")
	}

	// Download subnets
	networks, err := downloader.Download(urls)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to download subnets")
	}

	// Setup ipset
	if err := ipsetSvc.Setup(); err != nil {
		log.Fatal().Err(err).Msg("Failed to setup ipset")
	}

	// Fill ipset with subnets
	if err := ipsetSvc.Fill(networks); err != nil {
		log.Fatal().Err(err).Msg("Failed to fill ipset")
	}

	// Setup iptables
	if err := iptablesSvc.SetupChain(); err != nil {
		log.Fatal().Err(err).Msg("Failed to setup iptables")
	}

	// Setup logging if enabled
	if enableLogging {
		if err := loggingSvc.Setup(); err != nil {
			log.Warn().Err(err).Msg("Failed to setup logging configuration")
		}
	}

	// Save rules
	if err := ipsetSvc.Save("/etc/ipset.conf"); err != nil {
		log.Warn().Err(err).Msg("Failed to save ipset configuration")
	}

	// Create systemd service to restore ipset on boot (before UFW starts)
	if err := ipsetSvc.CreateRestoreService(); err != nil {
		log.Warn().Err(err).Msg("Failed to create ipset restore service")
	}

	if err := iptablesSvc.Save(); err != nil {
		log.Error().Msg("╔════════════════════════════════════════════════════════════╗")
		log.Error().Msg("║  ❌ УСТАНОВКА ПРЕРВАНА - КРИТИЧЕСКАЯ ОШИБКА                 ║")
		log.Error().Msg("╚════════════════════════════════════════════════════════════╝")
		log.Error().Msg("")
		log.Fatal().Err(err).Msg("Не удалось сохранить правила iptables")
	}

	cfg := &state.Config{
		URLs:           urls,
		EnableLogging:  enableLogging,
		AutoUpdate:     autoUpdate,
		UpdateInterval: updateInterval,
		LastUpdate:     time.Now(),
	}
	if err := state.Save(cfg); err != nil {
		log.Warn().Err(err).Msg("Не удалось сохранить state-файл")
	} else {
		log.Info().Str("path", state.Path()).Msg("Состояние сохранено")
	}

	if autoUpdate {
		updaterSvc := service.NewUpdaterService(log.Logger, cmdSvc)
		if err := updaterSvc.Setup(updateInterval); err != nil {
			log.Warn().Err(err).Msg("Не удалось настроить auto-update")
		}
	}

	log.Info().Msg("Полная установка успешно завершена")
}

func runUpdate(cmd *cobra.Command, args []string) {
	log := logger.Global()
	log.Info().Msg("=== Обновление списков блокировки ===")

	installer := service.NewInstallerService(log.Logger)
	if err := installer.CheckRootPrivileges(); err != nil {
		log.Fatal().Msg("Программа должна быть запущена от root (используйте sudo)")
	}

	cfg, err := state.Load()
	if err != nil {
		log.Fatal().Msg("Не сконфигурировано, запустите traffic-guard full")
	}

	cmdSvc := service.NewCommandService(log.Logger)
	downloader := service.NewDownloader(log.Logger)
	ipsetSvc := service.NewIpsetService(log.Logger, cmdSvc)

	networks, err := downloader.Download(cfg.URLs)
	if err != nil {
		log.Fatal().Err(err).Msg("Не удалось загрузить списки")
	}
	if networks.TotalCount() == 0 {
		log.Fatal().Msg("Получен пустой список, обновление отменено")
	}

	if err := ipsetSvc.Setup(); err != nil {
		log.Fatal().Err(err).Msg("Не удалось сбросить ipset")
	}
	if err := ipsetSvc.Fill(networks); err != nil {
		log.Fatal().Err(err).Msg("Не удалось заполнить ipset")
	}
	if err := ipsetSvc.Save("/etc/ipset.conf"); err != nil {
		log.Warn().Err(err).Msg("Не удалось сохранить конфигурацию ipset")
	}

	cfg.LastUpdate = time.Now()
	if err := state.Save(cfg); err != nil {
		log.Warn().Err(err).Msg("Не удалось обновить state-файл")
	}

	log.Info().
		Int("total", networks.TotalCount()).
		Msg("Списки блокировки успешно обновлены")
}

func runStatus(cmd *cobra.Command, args []string) {
	log := logger.Global()

	cmdSvc := service.NewCommandService(log.Logger)
	statusSvc := service.NewStatusService(log.Logger, cmdSvc)

	if err := statusSvc.Render(os.Stdout); err != nil {
		log.Fatal().Err(err).Msg("Не удалось получить статус")
	}
}

func runUninstall(cmd *cobra.Command, args []string) {
	log := logger.Global()
	log.Info().Msg("=== Удаление traffic-guard ===")

	cmdSvc := service.NewCommandService(log.Logger)
	installer := service.NewInstallerService(log.Logger)
	uninstaller := service.NewUninstallerService(log.Logger, cmdSvc)

	if err := installer.CheckRootPrivileges(); err != nil {
		log.Fatal().Msg("Программа должна быть запущена от root (используйте sudo)")
	}

	if !confirmYes {
		fmt.Print("Это удалит правила traffic-guard, systemd-сервисы и конфигурацию. Продолжить? [y/N]: ")
		if !confirmFromStdin() {
			log.Info().Msg("Удаление отменено пользователем")
			return
		}
	}

	if err := uninstaller.Uninstall(removeLogs); err != nil {
		log.Fatal().Err(err).Msg("Не удалось выполнить uninstall")
	}

	if removeLogs {
		log.Info().Msg("Uninstall завершён, логи удалены")
		return
	}

	log.Info().Msg("Uninstall завершён, логи сохранены")
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
