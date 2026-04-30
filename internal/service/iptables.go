package service

import (
	"fmt"
	"os"

	"github.com/rs/zerolog"
)

const (
	chainName = "SCANNERS-BLOCK"
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

// SetupChain creates and configures iptables chains
func (s *IptablesService) SetupChain() error {
	s.logger.Info().Msg("Настройка цепочек iptables")

	if err := s.setupVersionChain(IPv4, ipsetV4Name, true); err != nil {
		return fmt.Errorf("failed to setup IPv4 chain: %w", err)
	}

	if s.isDockerPresent() {
		if err := s.setupDockerUserChain(); err != nil {
			s.logger.Warn().Err(err).Msg("Не удалось настроить DOCKER-USER, продолжаем")
		}
	} else {
		s.logger.Info().Msg("Docker не обнаружен, настройка DOCKER-USER пропущена")
	}

	s.logger.Info().Msg("Цепочки iptables настроены")
	return nil
}

const dockerUserChain = "DOCKER-USER"

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
	if !s.iptablesCmd.ChainExists(IPv4, TableFilter, dockerUserChain) {
		s.logger.Info().Msg("Создание цепочки DOCKER-USER")
		if err := s.iptablesCmd.CreateChain(IPv4, TableFilter, dockerUserChain); err != nil {
			return fmt.Errorf("не удалось создать DOCKER-USER: %w", err)
		}
		// Add RETURN at the end so Docker behaviour is preserved if it appears later
		if err := s.iptablesCmd.AppendRule(IPv4, TableFilter, dockerUserChain, []string{"-j", "RETURN"}); err != nil {
			s.logger.Warn().Err(err).Msg("Не удалось добавить RETURN в DOCKER-USER")
		}
		justCreated = true
	}

	dropRule := []string{"-m", "set", "--match-set", ipsetV4Name, "src", "-j", "DROP"}
	if !s.iptablesCmd.RuleExists(IPv4, TableFilter, dockerUserChain, dropRule) {
		s.logger.Info().Msg("Вставка правила DROP в DOCKER-USER на позицию 1")
		if err := s.iptablesCmd.InsertRule(IPv4, TableFilter, dockerUserChain, 1, dropRule); err != nil {
			return fmt.Errorf("не удалось добавить правило в DOCKER-USER: %w", err)
		}
	} else if justCreated {
		s.logger.Debug().Msg("Правило DOCKER-USER уже присутствует")
	}

	if err := s.createDockerRuleService(); err != nil {
		s.logger.Warn().Err(err).Msg("Не удалось создать сервис antiscan-docker-rules")
	}
	return nil
}

// createDockerRuleService writes and enables antiscan-docker-rules.service and its timer.
func (s *IptablesService) createDockerRuleService() error {
	if err := os.WriteFile(DockerRulesServicePath, []byte(DockerRulesServiceTemplate), 0644); err != nil {
		return fmt.Errorf("запись %s: %w", DockerRulesServicePath, err)
	}
	if err := os.WriteFile(DockerRulesTimerPath, []byte(DockerRulesTimerTemplate), 0644); err != nil {
		return fmt.Errorf("запись %s: %w", DockerRulesTimerPath, err)
	}
	if err := s.cmdSvc.DaemonReload(); err != nil {
		s.logger.Warn().Err(err).Msg("daemon-reload завершился с ошибкой")
	}
	if err := s.cmdSvc.EnableService("antiscan-docker-rules.service"); err != nil {
		return fmt.Errorf("включение antiscan-docker-rules.service: %w", err)
	}
	if err := s.cmdSvc.Run("systemctl", "enable", "--now", "antiscan-docker-rules.timer"); err != nil {
		s.logger.Warn().Err(err).Msg("Не удалось включить antiscan-docker-rules.timer")
	}
	s.logger.Info().Msg("Сервис и таймер antiscan-docker-rules включены")
	return nil
}

// setupVersionChain configures the SCANNERS-BLOCK chain
func (s *IptablesService) setupVersionChain(version IPVersion, ipsetName string, linkToInput bool) error {
	s.logger.Debug().Str("version", string(version)).Msg("Настройка цепочки")

	if s.iptablesCmd.ChainExists(version, TableFilter, chainName) {
		s.logger.Info().Str("chain", chainName).Str("version", string(version)).Msg("Очистка существующей цепочки")
		if err := s.iptablesCmd.FlushChain(version, TableFilter, chainName); err != nil {
			return fmt.Errorf("failed to flush chain: %w", err)
		}
	} else {
		s.logger.Info().Str("chain", chainName).Str("version", string(version)).Msg("Создание цепочки")
		if err := s.iptablesCmd.CreateChain(version, TableFilter, chainName); err != nil {
			return fmt.Errorf("failed to create chain: %w", err)
		}
	}

	if linkToInput {
		if !s.iptablesCmd.RuleExists(version, TableFilter, string(ChainInput), []string{"-j", chainName}) {
			s.logger.Info().Str("version", string(version)).Msg("Привязка цепочки к INPUT")
			if err := s.iptablesCmd.LinkChainToInput(version, chainName, 1); err != nil {
				return fmt.Errorf("failed to link chain to INPUT: %w", err)
			}
		}
	}

	establishedRule := NewRuleBuilder().
		MatchConntrack("ESTABLISHED", "RELATED").
		Jump(TargetReturn).
		Build()
	if !s.iptablesCmd.RuleExists(version, TableFilter, chainName, establishedRule) {
		s.logger.Info().Str("version", string(version)).Msg("Добавление правила для установленных соединений")
		if err := s.iptablesCmd.InsertRule(version, TableFilter, chainName, 1, establishedRule); err != nil {
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
		if !s.iptablesCmd.RuleExists(version, TableFilter, chainName, logRule) {
			s.logger.Info().Str("version", string(version)).Msg("Добавление правила логирования")
			if err := s.iptablesCmd.InsertRule(version, TableFilter, chainName, 2, logRule); err != nil {
				return fmt.Errorf("failed to add LOG rule: %w", err)
			}
		}
	}

	dropRule := NewRuleBuilder().MatchSet(ipsetName, "src").Jump(TargetDrop).Build()
	if !s.iptablesCmd.RuleExists(version, TableFilter, chainName, dropRule) {
		s.logger.Info().Str("version", string(version)).Msg("Добавление правила блокировки")
		if err := s.iptablesCmd.AppendRule(version, TableFilter, chainName, dropRule); err != nil {
			return fmt.Errorf("failed to add DROP rule: %w", err)
		}
	}

	return nil
}

// Save saves iptables rules using netfilter-persistent
func (s *IptablesService) Save() error {
	s.logger.Info().Msg("Сохранение правил iptables")

	if !s.cmdSvc.CommandExists("netfilter-persistent") {
		return fmt.Errorf("netfilter-persistent не установлен. Запустите установку зависимостей")
	}

	return s.saveWithNetfilterPersistent()
}

// saveWithNetfilterPersistent saves using netfilter-persistent
func (s *IptablesService) saveWithNetfilterPersistent() error {
	if err := os.MkdirAll("/etc/iptables", 0755); err != nil {
		return fmt.Errorf("failed to create /etc/iptables: %w", err)
	}

	if err := s.iptablesCmd.Save(IPv4, "/etc/iptables/rules.v4"); err != nil {
		return fmt.Errorf("failed to save iptables: %w", err)
	}
	s.logger.Info().Msg("Правила iptables сохранены в /etc/iptables/rules.v4")

	if err := s.cmdSvc.Run("netfilter-persistent", "save"); err != nil {
		s.logger.Warn().Err(err).Msg("netfilter-persistent save failed")
	}

	return nil
}
