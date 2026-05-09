// Copyright 2026 Optiqor contributors
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/optiqor/kerno/internal/ai"
	"github.com/optiqor/kerno/internal/bpf"
	"github.com/optiqor/kerno/internal/collector"
	"github.com/optiqor/kerno/internal/config"
	"github.com/optiqor/kerno/internal/doctor"
)

func newDoctorCmd() *cobra.Command {
	var (
		duration   time.Duration
		exitCode   bool
		continuous bool
		interval   time.Duration
		output     string
		useAI      bool
		noAI       bool
	)

	cmd := &cobra.Command{
		Use:   "doctor",
		Short: "Run a 30-second automated kernel diagnostic",
		Long: `Kerno Doctor collects kernel signals via eBPF for 30 seconds (configurable),
analyzes them against diagnostic rules, and prints a ranked report of findings.

This is the primary entry point for kernel troubleshooting. No configuration needed.
Add --ai to enrich findings with AI-powered analysis (requires API key).`,
		Example: `  # Run a standard 30-second diagnostic
  sudo kerno doctor

  # Quick 10-second check
  sudo kerno doctor --duration 10s

  # Machine-readable output for CI/CD
  sudo kerno doctor --output json --exit-code

  # Continuous monitoring
  sudo kerno doctor --continuous --interval 60s

  # Enable AI analysis
  sudo kerno doctor --ai`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			// Inherit --output from root if not set via doctor flag.
			if output == "" {
				output, _ = cmd.Root().PersistentFlags().GetString("output")
			}

			// Resolve AI enable/disable: --ai flag overrides config, --no-ai forces off.
			aiEnabled := cfg.AI.Enabled
			if useAI {
				aiEnabled = true
			}
			if noAI {
				aiEnabled = false
			}

			return runDoctor(cmd.Context(), doctorOpts{
				duration:   duration,
				exitCode:   exitCode,
				continuous: continuous,
				interval:   interval,
				output:     output,
				aiEnabled:  aiEnabled,
			})
		},
	}

	flags := cmd.Flags()
	flags.DurationVarP(&duration, "duration", "d", 0, "analysis duration (default: from config, typically 30s)")
	flags.BoolVar(&exitCode, "exit-code", false, "exit 1 if critical findings exist (for CI/CD)")
	flags.BoolVar(&continuous, "continuous", false, "re-run analysis at regular intervals")
	flags.DurationVar(&interval, "interval", 60*time.Second, "interval between runs in continuous mode")
	flags.StringVarP(&output, "output", "o", "", "output format: pretty, json (overrides global --output)")
	flags.BoolVar(&useAI, "ai", false, "enable AI-powered analysis (requires API key)")
	flags.BoolVar(&noAI, "no-ai", false, "disable AI analysis even if enabled in config")

	return cmd
}

type doctorOpts struct {
	duration   time.Duration
	exitCode   bool
	continuous bool
	interval   time.Duration
	output     string
	aiEnabled  bool
}

func runDoctor(ctx context.Context, opts doctorOpts) error {
	// Use config default if no flag override.
	if opts.duration == 0 {
		if cfg != nil {
			opts.duration = cfg.Doctor.Duration
		} else {
			opts.duration = 30 * time.Second
		}
	}
	if opts.output == "" {
		opts.output = "pretty"
	}

	logger := slog.Default()

	// Resolve thresholds from config.
	thresholds := cfg.Doctor.Thresholds

	// Build optional AI analyzer.
	var analyzer doctor.Analyzer
	if opts.aiEnabled {
		var err error
		analyzer, err = buildAnalyzer(cfg, logger)
		if err != nil {
			// AI setup failure is non-fatal — warn and continue without AI.
			logger.Warn("AI analysis unavailable, continuing with rule-based diagnostics", "error", err)
		}
	}

	// Create the diagnostic engine.
	engine := doctor.NewEngine(thresholds, analyzer, logger)

	// Select renderer.
	var renderer doctor.Renderer
	switch opts.output {
	case "json":
		renderer = &doctor.JSONRenderer{Pretty: true}
	default:
		renderer = &doctor.PrettyRenderer{
			NoColor: os.Getenv("NO_COLOR") != "" || !isTerminal(),
		}
	}

	// Build the eBPF loader set + collector registry. Loader failures are
	// non-fatal — we degrade gracefully and surface the gap in the report.
	registry, closers, loadedCount, totalCount := buildCollectors(logger)
	defer func() {
		for _, c := range closers {
			c()
		}
	}()

	if loadedCount == 0 && totalCount > 0 {
		// Nothing loaded. Common causes: not root, no BTF, kernel too old.
		// Still run the cycle so the renderer can show the empty/healthy
		// state with the program count footer — useful diagnostic itself.
		logger.Warn("no eBPF programs loaded; report will reflect zero signals",
			"hint", "check root privileges, /sys/kernel/btf/vmlinux, and kernel >= 5.8")
	}

	// Run the diagnostic loop (once, or continuous).
	for {
		if err := runDiagnosticCycle(ctx, engine, registry, renderer, opts, logger); err != nil {
			return err
		}

		if !opts.continuous {
			break
		}

		logger.Info("waiting for next cycle", "interval", opts.interval)
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(opts.interval):
		}
	}

	return nil
}

// noopCloser satisfies io.Closer with a no-op Close. Used by collectors
// that don't load any eBPF program (e.g. the procfs-based memory
// collector) so the registration table can stay uniform.
type noopCloser struct{}

func (noopCloser) Close() error { return nil }

// buildCollectors loads all enabled eBPF programs and registers a
// matching live collector for each. Loaders that fail to load are
// skipped (graceful degradation). Returns the registry, a list of
// cleanup closures (idempotent), and counters for the report footer.
func buildCollectors(logger *slog.Logger) (*collector.Registry, []func(), int, int) {
	registry := collector.NewRegistry(logger)
	var closers []func()

	type loaderRegistration struct {
		name    string
		enabled bool
		// build creates the loader, calls Load() on it, and returns a
		// Collector ready to be registered. On Load() failure, returns
		// (nil, nil, error) so the caller can log + skip.
		build func() (collector.Collector, io.Closer, error)
	}

	registrations := []loaderRegistration{
		{
			name:    "syscall_latency",
			enabled: cfg.Collectors.SyscallLatency,
			build: func() (collector.Collector, io.Closer, error) {
				l := bpf.NewSyscallLatencyLoader(logger)
				closer, err := l.Load()
				if err != nil {
					return nil, nil, err
				}
				return collector.NewSyscallCollector(logger, l), closer, nil
			},
		},
		{
			name:    "tcp_monitor",
			enabled: cfg.Collectors.TCPMonitor,
			build: func() (collector.Collector, io.Closer, error) {
				l := bpf.NewTCPMonitorLoader(logger)
				closer, err := l.Load()
				if err != nil {
					return nil, nil, err
				}
				return collector.NewTCPCollector(logger, l), closer, nil
			},
		},
		{
			name:    "oom_track",
			enabled: cfg.Collectors.OOMTrack,
			build: func() (collector.Collector, io.Closer, error) {
				l := bpf.NewOOMTrackLoader(logger)
				closer, err := l.Load()
				if err != nil {
					return nil, nil, err
				}
				return collector.NewOOMCollector(logger, l), closer, nil
			},
		},
		{
			name:    "disk_io",
			enabled: cfg.Collectors.DiskIO,
			build: func() (collector.Collector, io.Closer, error) {
				l := bpf.NewDiskIOLoader(logger)
				closer, err := l.Load()
				if err != nil {
					return nil, nil, err
				}
				return collector.NewDiskIOCollector(logger, l), closer, nil
			},
		},
		{
			name:    "sched_delay",
			enabled: cfg.Collectors.SchedDelay,
			build: func() (collector.Collector, io.Closer, error) {
				l := bpf.NewSchedDelayLoader(logger)
				closer, err := l.Load()
				if err != nil {
					return nil, nil, err
				}
				return collector.NewSchedCollector(logger, l), closer, nil
			},
		},
		{
			name:    "fd_track",
			enabled: cfg.Collectors.FDTrack,
			build: func() (collector.Collector, io.Closer, error) {
				l := bpf.NewFDTrackLoader(logger)
				closer, err := l.Load()
				if err != nil {
					return nil, nil, err
				}
				return collector.NewFDCollector(logger, l), closer, nil
			},
		},
		{
			// Memory collector polls /proc/meminfo — it doesn't load
			// any eBPF program, so the build closure returns a no-op
			// io.Closer.
			name:    "memory",
			enabled: true,
			build: func() (collector.Collector, io.Closer, error) {
				return collector.NewMemoryCollector(logger, 0), noopCloser{}, nil
			},
		},
	}

	loaded, total := 0, 0
	for _, r := range registrations {
		if !r.enabled {
			continue
		}
		total++
		coll, closer, err := r.build()
		if err != nil {
			logger.Warn("failed to load eBPF program; collector disabled",
				"program", r.name, "error", err)
			continue
		}
		closers = append(closers, func() { _ = closer.Close() })
		if err := registry.Register(coll); err != nil {
			logger.Warn("failed to register collector", "name", coll.Name(), "error", err)
			continue
		}
		loaded++
	}

	return registry, closers, loaded, total
}

// buildAnalyzer constructs the AI analyzer from configuration.
func buildAnalyzer(c *config.Config, logger *slog.Logger) (doctor.Analyzer, error) {
	aiCfg := c.AI

	// Build the LLM provider.
	provider, err := ai.NewProvider(ai.ProviderConfig{
		Name:        aiCfg.Provider,
		Model:       aiCfg.Model,
		APIKey:      aiCfg.APIKey,
		Endpoint:    aiCfg.Endpoint,
		MaxTokens:   aiCfg.MaxTokens,
		Temperature: aiCfg.Temperature,
	})
	if err != nil {
		return nil, fmt.Errorf("creating AI provider: %w", err)
	}

	// Wrap with rate limiter.
	if aiCfg.RateLimitPerMinute > 0 {
		provider = ai.NewRateLimitedProvider(provider, aiCfg.RateLimitPerMinute)
	}

	// Build the cache.
	var cache *ai.Cache
	if aiCfg.CacheTTL != "" {
		ttl, err := time.ParseDuration(aiCfg.CacheTTL)
		if err != nil {
			logger.Warn("invalid ai.cache_ttl, using 5m default", "value", aiCfg.CacheTTL, "error", err)
			ttl = 5 * time.Minute
		}
		cache = ai.NewCache(ttl)
	}

	// Resolve privacy mode.
	privacy := ai.PrivacyMode(aiCfg.PrivacyMode)
	if privacy == "" {
		privacy = ai.PrivacySummary
	}

	return ai.NewAnalyzer(ai.AnalyzerConfig{
		Provider: provider,
		Cache:    cache,
		Privacy:  privacy,
		Logger:   logger,
	}), nil
}

func runDiagnosticCycle(
	ctx context.Context,
	engine *doctor.Engine,
	registry *collector.Registry,
	renderer doctor.Renderer,
	opts doctorOpts,
	logger *slog.Logger,
) error {
	logger.Info("starting kernel diagnostic",
		"duration", opts.duration,
		"ai", opts.aiEnabled,
	)

	// Phase 1: Start collectors and let them consume events for the
	// configured duration. Each collector runs its own goroutine driven
	// by the loader's ringbuf; we just bound the lifetime here.
	collectCtx, cancel := context.WithTimeout(ctx, opts.duration)
	defer cancel()

	if err := registry.StartAll(collectCtx); err != nil {
		// A collector failing to start is non-fatal — log and continue.
		// Snapshot() on an unstarted collector still returns a zero-value
		// snapshot, which the rule engine handles cleanly.
		logger.Warn("one or more collectors failed to start", "error", err)
	}
	defer registry.StopAll()

	// Show progress to user (stderr so it doesn't pollute JSON output).
	if opts.output != "json" {
		fmt.Fprintf(os.Stderr, "Collecting kernel signals for %s...\n", opts.duration)
	}

	// Wait for collection window to complete.
	<-collectCtx.Done()

	// Check if we were canceled by the parent context (Ctrl+C) vs timeout.
	if ctx.Err() != nil {
		if opts.output != "json" {
			fmt.Fprintf(os.Stderr, "Interrupted — analyzing partial data.\n")
		}
	}

	// Phase 2: Gather combined signal snapshot from all collectors.
	signals := registry.Signals(opts.duration)

	// Phase 3: Run diagnostic engine (rules + optional AI).
	report, err := engine.Diagnose(ctx, signals)
	if err != nil {
		return fmt.Errorf("diagnosis failed: %w", err)
	}

	// Phase 4: Render the report.
	if err := renderer.Render(os.Stdout, report); err != nil {
		return fmt.Errorf("rendering report: %w", err)
	}

	// Phase 5: Exit code handling for CI/CD.
	if opts.exitCode && report.HasCritical() {
		return &exitError{code: 1}
	}

	return nil
}

// exitError is returned when --exit-code is set and critical findings exist.
type exitError struct {
	code int
}

func (e *exitError) Error() string {
	return fmt.Sprintf("critical findings detected (exit code %d)", e.code)
}

// ExitCode returns the exit code for this error.
func (e *exitError) ExitCode() int {
	return e.code
}
