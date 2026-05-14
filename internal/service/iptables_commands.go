package service

import (
	"fmt"
	"strings"

	"github.com/rs/zerolog"
)

// IptablesCommandService provides high-level iptables operations (IPv4 only).
type IptablesCommandService struct {
	logger zerolog.Logger
	cmdSvc *CommandService
}

// NewIptablesCommandService creates a new iptables command service
func NewIptablesCommandService(logger zerolog.Logger, cmdSvc *CommandService) *IptablesCommandService {
	return &IptablesCommandService{
		logger: logger,
		cmdSvc: cmdSvc,
	}
}

// Table represents iptables table
type Table string

const (
	TableFilter Table = "filter"
)

// Chain represents iptables chain
type Chain string

const (
	ChainInput Chain = "INPUT"
)

// Target represents iptables target
type Target string

const (
	TargetDrop   Target = "DROP"
	TargetLog    Target = "LOG"
	TargetReturn Target = "RETURN"
)

const iptablesCmd = "iptables"

// CreateChain creates a new chain
func (s *IptablesCommandService) CreateChain(table Table, chainName string) error {
	s.logger.Debug().
		Str("table", string(table)).
		Str("chain", chainName).
		Msg("Creating chain")

	return s.cmdSvc.Run(iptablesCmd, "-t", string(table), "-N", chainName)
}

// DeleteChain deletes a chain
func (s *IptablesCommandService) DeleteChain(table Table, chainName string) error {
	s.logger.Debug().
		Str("table", string(table)).
		Str("chain", chainName).
		Msg("Deleting chain")

	return s.cmdSvc.Run(iptablesCmd, "-t", string(table), "-X", chainName)
}

// FlushChain flushes all rules from a chain
func (s *IptablesCommandService) FlushChain(table Table, chainName string) error {
	s.logger.Debug().
		Str("table", string(table)).
		Str("chain", chainName).
		Msg("Flushing chain")

	return s.cmdSvc.Run(iptablesCmd, "-t", string(table), "-F", chainName)
}

// ChainExists checks if a chain exists
func (s *IptablesCommandService) ChainExists(table Table, chainName string) bool {
	_, err := s.cmdSvc.RunOutputQuiet(iptablesCmd, "-t", string(table), "-L", chainName, "-n")
	return err == nil
}

// RuleExists checks if a rule exists in a chain
func (s *IptablesCommandService) RuleExists(table Table, chainName string, ruleSpec []string) bool {
	args := append([]string{"-t", string(table), "-C", chainName}, ruleSpec...)
	return s.cmdSvc.RunQuiet(iptablesCmd, args...) == nil
}

// AppendRule appends a rule to a chain
func (s *IptablesCommandService) AppendRule(table Table, chainName string, ruleSpec []string) error {
	s.logger.Debug().
		Str("chain", chainName).
		Strs("rule", ruleSpec).
		Msg("Appending rule")

	args := append([]string{"-t", string(table), "-A", chainName}, ruleSpec...)
	return s.cmdSvc.Run(iptablesCmd, args...)
}

// InsertRule inserts a rule at the beginning of a chain
func (s *IptablesCommandService) InsertRule(table Table, chainName string, position int, ruleSpec []string) error {
	s.logger.Debug().
		Str("chain", chainName).
		Int("position", position).
		Strs("rule", ruleSpec).
		Msg("Inserting rule")

	args := []string{"-t", string(table), "-I", chainName}
	if position > 0 {
		args = append(args, fmt.Sprintf("%d", position))
	}
	args = append(args, ruleSpec...)
	return s.cmdSvc.Run(iptablesCmd, args...)
}

// DeleteRule deletes a rule from a chain
func (s *IptablesCommandService) DeleteRule(table Table, chainName string, ruleSpec []string) error {
	s.logger.Debug().
		Str("chain", chainName).
		Strs("rule", ruleSpec).
		Msg("Deleting rule")

	args := append([]string{"-t", string(table), "-D", chainName}, ruleSpec...)
	return s.cmdSvc.Run(iptablesCmd, args...)
}

// DeleteRuleByNumber deletes a rule by its number in the chain
func (s *IptablesCommandService) DeleteRuleByNumber(table Table, chainName string, ruleNum int) error {
	s.logger.Debug().
		Str("chain", chainName).
		Int("rule_number", ruleNum).
		Msg("Deleting rule by number")

	return s.cmdSvc.Run(iptablesCmd, "-t", string(table), "-D", chainName, fmt.Sprintf("%d", ruleNum))
}

// ListChain lists all rules in a chain
func (s *IptablesCommandService) ListChain(table Table, chainName string) (string, error) {
	s.logger.Debug().
		Str("table", string(table)).
		Str("chain", chainName).
		Msg("Listing chain")

	return s.cmdSvc.RunOutput(iptablesCmd, "-t", string(table), "-L", chainName, "-n", "-v")
}

// Save saves iptables rules to a file
func (s *IptablesCommandService) Save(path string) error {
	s.logger.Info().Str("path", path).Msg("Saving iptables rules")
	return s.cmdSvc.RunToFile(path, "iptables-save")
}

// RuleBuilder helps build iptables rules
type RuleBuilder struct {
	spec []string
}

// NewRuleBuilder creates a new rule builder
func NewRuleBuilder() *RuleBuilder {
	return &RuleBuilder{
		spec: make([]string, 0),
	}
}

// MatchSet adds ipset match
func (rb *RuleBuilder) MatchSet(setName, flag string) *RuleBuilder {
	rb.spec = append(rb.spec, "-m", "set", "--match-set", setName, flag)
	return rb
}

// MatchConntrack adds a connection state match (-m conntrack --ctstate ...)
func (rb *RuleBuilder) MatchConntrack(states ...string) *RuleBuilder {
	rb.spec = append(rb.spec, "-m", "conntrack", "--ctstate", strings.Join(states, ","))
	return rb
}

// MatchLimit adds rate limiting
func (rb *RuleBuilder) MatchLimit(rate, burst string) *RuleBuilder {
	rb.spec = append(rb.spec, "-m", "limit", "--limit", rate)
	if burst != "" {
		rb.spec = append(rb.spec, "--limit-burst", burst)
	}
	return rb
}

// Jump sets the target/jump
func (rb *RuleBuilder) Jump(target Target) *RuleBuilder {
	rb.spec = append(rb.spec, "-j", string(target))
	return rb
}

// JumpChain sets jump to a custom chain
func (rb *RuleBuilder) JumpChain(chainName string) *RuleBuilder {
	rb.spec = append(rb.spec, "-j", chainName)
	return rb
}

// LogPrefix sets log prefix
func (rb *RuleBuilder) LogPrefix(prefix string) *RuleBuilder {
	rb.spec = append(rb.spec, "--log-prefix", prefix)
	return rb
}

// LogLevel sets log level
func (rb *RuleBuilder) LogLevel(level string) *RuleBuilder {
	rb.spec = append(rb.spec, "--log-level", level)
	return rb
}

// Build returns the rule specification
func (rb *RuleBuilder) Build() []string {
	return rb.spec
}

// LinkChainToInput inserts a jump to chainName at the given position of INPUT.
func (s *IptablesCommandService) LinkChainToInput(chainName string, position int) error {
	rule := NewRuleBuilder().JumpChain(chainName).Build()
	return s.InsertRule(TableFilter, string(ChainInput), position, rule)
}

// UnlinkChainFromInput removes the jump to chainName from INPUT.
func (s *IptablesCommandService) UnlinkChainFromInput(chainName string) error {
	rule := NewRuleBuilder().JumpChain(chainName).Build()
	return s.DeleteRule(TableFilter, string(ChainInput), rule)
}
