package service

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/serj1974-maker/antiscan/internal/state"
	"github.com/rs/zerolog"
)

// StatusService renders the current antiscan-simple protection state.
type StatusService struct {
	logger      zerolog.Logger
	cmdSvc      *CommandService
	iptablesCmd *IptablesCommandService
	ipsetCmd    *IpsetCommandService
}

// NewStatusService creates a new status service.
func NewStatusService(logger zerolog.Logger, cmdSvc *CommandService) *StatusService {
	return &StatusService{
		logger:      logger,
		cmdSvc:      cmdSvc,
		iptablesCmd: NewIptablesCommandService(logger, cmdSvc),
		ipsetCmd:    NewIpsetCommandService(logger, cmdSvc),
	}
}

// Render writes a human-readable status report to w.
func (s *StatusService) Render(w io.Writer) error {
	chainExists := s.iptablesCmd.ChainExists(TableFilter, chainName)
	attachedTo := s.collectAttachments()

	active := chainExists && len(attachedTo) > 0
	if active {
		fmt.Fprintln(w, "Protection: active")
		fmt.Fprintf(w, "  Attached to: %s\n", strings.Join(attachedTo, ", "))
	} else {
		fmt.Fprintln(w, "Protection: inactive")
		if chainExists && len(attachedTo) == 0 {
			fmt.Fprintln(w, "  Chain SCANNERS-BLOCK exists but is not linked to INPUT/DOCKER-USER")
		}
		if !chainExists {
			fmt.Fprintln(w, "  Chain SCANNERS-BLOCK is missing")
		}
	}

	v4Count, v4Err := s.ipsetEntryCount(ipsetV4Name)
	fmt.Fprintln(w)
	fmt.Fprintln(w, "ipset sizes:")
	fmt.Fprintf(w, "  %s: %s\n", ipsetV4Name, formatCount(v4Count, v4Err))

	fmt.Fprintln(w)
	cfg, err := state.Load()
	switch {
	case errors.Is(err, state.ErrNotFound):
		fmt.Fprintln(w, "Source lists: not configured — run antiscan-simple full")
		fmt.Fprintln(w, "Last update: —")
	case err != nil:
		fmt.Fprintf(w, "Source lists: error reading state: %v\n", err)
		fmt.Fprintln(w, "Last update: —")
	default:
		fmt.Fprintln(w, "Source lists:")
		if len(cfg.URLs) == 0 {
			fmt.Fprintln(w, "  (empty)")
		}
		for _, url := range cfg.URLs {
			fmt.Fprintf(w, "  - %s\n", url)
		}
		fmt.Fprintf(w, "Last update: %s\n", formatLastUpdate(cfg.LastUpdate))
		if cfg.AutoUpdate {
			fmt.Fprintf(w, "Auto-update: enabled, interval %s\n", cfg.UpdateInterval)
		} else {
			fmt.Fprintln(w, "Auto-update: disabled")
		}
	}

	fmt.Fprintln(w)
	pkts, err := s.blockedPackets()
	if err != nil {
		fmt.Fprintf(w, "Blocked packets (IPv4): unknown (%v)\n", err)
	} else {
		fmt.Fprintf(w, "Blocked packets (IPv4): %d\n", pkts)
	}

	return nil
}

// collectAttachments returns user-friendly names of chains that jump to SCANNERS-BLOCK (IPv4).
func (s *StatusService) collectAttachments() []string {
	var found []string
	candidates := []string{"INPUT", "DOCKER-USER"}
	for _, chain := range candidates {
		if s.iptablesCmd.RuleExists(TableFilter, chain, []string{"-j", chainName}) {
			found = append(found, chain)
		}
	}
	return found
}

// ipsetEntryCount parses "Number of entries:" from `ipset list -t <name>`.
func (s *StatusService) ipsetEntryCount(setName string) (int, error) {
	out, err := s.cmdSvc.RunOutputQuiet("ipset", "list", "-t", setName)
	if err != nil {
		return 0, fmt.Errorf("ipset list: %w", err)
	}
	return parseIpsetEntries(out)
}

// blockedPackets sums packet counters from DROP rules in SCANNERS-BLOCK (IPv4).
func (s *StatusService) blockedPackets() (uint64, error) {
	out, err := s.cmdSvc.RunOutput("iptables", "-L", chainName, "-v", "-n", "-x")
	if err != nil {
		return 0, fmt.Errorf("iptables -L: %w", err)
	}
	return parseDropPackets(out), nil
}

func parseIpsetEntries(output string) (int, error) {
	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if !strings.HasPrefix(line, "Number of entries:") {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		n, err := strconv.Atoi(strings.TrimSpace(parts[1]))
		if err != nil {
			return 0, fmt.Errorf("parse entries count: %w", err)
		}
		return n, nil
	}
	return 0, fmt.Errorf("'Number of entries:' not found")
}

// parseDropPackets sums the first column (pkts) for each DROP rule line.
//
// Output of `iptables -L CHAIN -v -n -x` looks like:
//
//	Chain SCANNERS-BLOCK (1 references)
//	    pkts      bytes target ...
//	      42       3000 DROP   all  --  *  *  0.0.0.0/0  0.0.0.0/0  match-set SCANNERS-BLOCK-V4 src
func parseDropPackets(output string) uint64 {
	var total uint64
	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 3 {
			continue
		}
		if fields[2] != "DROP" {
			continue
		}
		n, err := strconv.ParseUint(fields[0], 10, 64)
		if err != nil {
			continue
		}
		total += n
	}
	return total
}

func formatCount(n int, err error) string {
	if err != nil {
		return fmt.Sprintf("unknown (%v)", err)
	}
	return strconv.Itoa(n)
}

func formatLastUpdate(t time.Time) string {
	if t.IsZero() {
		return "—"
	}
	d := time.Since(t)
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%d seconds ago (%s)", int(d.Seconds()), t.Format(time.RFC3339))
	case d < time.Hour:
		return fmt.Sprintf("%d minutes ago (%s)", int(d.Minutes()), t.Format(time.RFC3339))
	case d < 24*time.Hour:
		return fmt.Sprintf("%d hours ago (%s)", int(d.Hours()), t.Format(time.RFC3339))
	default:
		return fmt.Sprintf("%d days ago (%s)", int(d.Hours()/24), t.Format(time.RFC3339))
	}
}
