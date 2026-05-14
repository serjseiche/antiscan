package service

import (
	"fmt"

	"github.com/rs/zerolog"
)

// IpsetCommandService provides high-level ipset operations
type IpsetCommandService struct {
	logger zerolog.Logger
	cmdSvc *CommandService
}

// NewIpsetCommandService creates a new ipset command service
func NewIpsetCommandService(logger zerolog.Logger, cmdSvc *CommandService) *IpsetCommandService {
	return &IpsetCommandService{
		logger: logger,
		cmdSvc: cmdSvc,
	}
}

// SetType represents ipset set type
type SetType string

const (
	SetTypeHashNet SetType = "hash:net"
)

// Family represents IP family
type Family string

// CreateSetOptions contains options for creating an ipset set
type CreateSetOptions struct {
	Name     string
	Type     SetType
	Family   Family
	HashSize int
	MaxElem  int
	Timeout  int // seconds, 0 means no timeout
	Comment  bool
}

// Create creates a new ipset set
func (s *IpsetCommandService) Create(opts CreateSetOptions) error {
	s.logger.Debug().
		Str("name", opts.Name).
		Str("type", string(opts.Type)).
		Str("family", string(opts.Family)).
		Msg("Creating ipset set")

	args := []string{"create", opts.Name, string(opts.Type)}

	if opts.Family != "" {
		args = append(args, "family", string(opts.Family))
	}

	if opts.HashSize > 0 {
		args = append(args, "hashsize", fmt.Sprintf("%d", opts.HashSize))
	}

	if opts.MaxElem > 0 {
		args = append(args, "maxelem", fmt.Sprintf("%d", opts.MaxElem))
	}

	if opts.Timeout > 0 {
		args = append(args, "timeout", fmt.Sprintf("%d", opts.Timeout))
	}

	if opts.Comment {
		args = append(args, "comment")
	}

	return s.cmdSvc.Run("ipset", args...)
}

// Destroy destroys an ipset set
func (s *IpsetCommandService) Destroy(name string) error {
	s.logger.Debug().Str("name", name).Msg("Destroying ipset set")
	return s.cmdSvc.Run("ipset", "destroy", name)
}

// Flush flushes all entries from an ipset set
func (s *IpsetCommandService) Flush(name string) error {
	s.logger.Debug().Str("name", name).Msg("Flushing ipset set")
	return s.cmdSvc.Run("ipset", "flush", name)
}

// Add adds an entry to an ipset set
func (s *IpsetCommandService) Add(setName, entry string) error {
	return s.cmdSvc.Run("ipset", "add", setName, entry)
}

// List lists entries in an ipset set
func (s *IpsetCommandService) List(name string) (string, error) {
	s.logger.Debug().Str("name", name).Msg("Listing ipset set")
	return s.cmdSvc.RunOutput("ipset", "list", name)
}

// Exists checks if an ipset set exists
func (s *IpsetCommandService) Exists(name string) bool {
	_, err := s.cmdSvc.RunOutputQuiet("ipset", "list", name)
	return err == nil
}

// Save saves ipset configuration to a file
func (s *IpsetCommandService) Save(path string) error {
	s.logger.Info().Str("path", path).Msg("Saving ipset configuration")
	return s.cmdSvc.RunToFile(path, "ipset", "save")
}

// CreateHashNet creates a hash:net type set (convenience method)
func (s *IpsetCommandService) CreateHashNet(name string, family Family, hashSize, maxElem int) error {
	return s.Create(CreateSetOptions{
		Name:     name,
		Type:     SetTypeHashNet,
		Family:   family,
		HashSize: hashSize,
		MaxElem:  maxElem,
	})
}
