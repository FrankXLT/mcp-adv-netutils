package dispatch

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/FrankXLT/mcp-adv-netutils/internal/cronmon"
	"github.com/FrankXLT/mcp-adv-netutils/internal/store"
)

// DestinationParams defines inputs for managing or executing persisted saved destinations.
type DestinationParams struct {
	Action          string `json:"action"`
	ID              string `json:"id,omitempty"`
	Name            string `json:"name,omitempty"`
	Target          string `json:"target,omitempty"`
	Category        string `json:"category,omitempty"`
	MAC             string `json:"mac,omitempty"`
	ClearMAC        bool   `json:"clear_mac,omitempty"`
	DefaultCheck    string `json:"default_check,omitempty"`
	Pinned          *bool  `json:"pinned,omitempty"`
	MonitorEnabled  *bool  `json:"monitor_enabled,omitempty"`
	MonitorSchedule string `json:"monitor_schedule,omitempty"`
	Style           string `json:"style,omitempty"`
}

// DestinationResult reports the outcome of a ManageSavedDestinations invocation.
type DestinationResult struct {
	Action  string                   `json:"action"`
	Item    *store.SavedDestination  `json:"item,omitempty"`
	Items   []store.SavedDestination `json:"items,omitempty"`
	Outcome *Outcome                 `json:"outcome,omitempty"`
}

const (
	destCronPrefix         = "dest_"
	defaultDestCheckTool   = "recipe_diff_ping"
	defaultMonitorSchedule = "*/5 * * * *"
)

var disallowedDestChecks = map[string]struct{}{
	"unlock_netutils": {}, "lock_netutils": {}, "manage_saved_destinations": {},
	"manage_cron_watchlist": {}, "get_cron_status": {}, "get_job_report": {}, "render_run_digest": {},
}

// ManageSavedDestinations performs list, save, delete, or run operations against persisted destinations,
// validating targets with TargetGuard and synchronizing recurring monitor schedules with cronmon.Scheduler.
//
//nolint:gocritic // hugeParam: DestinationParams value signature matches public dispatch contract.
func (d *Dispatcher) ManageSavedDestinations(ctx context.Context, p DestinationParams) (*DestinationResult, error) {
	return d.manageSavedDestinations(ctx, &p, false)
}

// RunSavedDestination executes a saved destination's DefaultCheck via Dispatch and returns the Outcome.
func (d *Dispatcher) RunSavedDestination(ctx context.Context, id, style, source string, skipDeadbolt bool) (*Outcome, error) {
	if ctx == nil || d.jobStore == nil {
		return nil, errors.New("context and job store are required")
	}
	dst, err := d.resolveDestination(ctx, id, "")
	if err != nil {
		return nil, err
	}
	return d.runSavedDestination(ctx, dst, style, source, skipDeadbolt)
}

// ReconcileDestinationMonitors synchronizes all persisted MonitorEnabled destinations
// from SQLite into the attached cronmon.Scheduler.
func (d *Dispatcher) ReconcileDestinationMonitors(ctx context.Context) error {
	if ctx == nil {
		return errors.New("context must not be nil")
	}
	d.destMu.Lock()
	defer d.destMu.Unlock()

	if d.jobStore == nil || d.Scheduler() == nil {
		return nil
	}
	items, err := d.jobStore.ListDestinations(ctx)
	if err != nil {
		return fmt.Errorf("list destinations for monitor reconciliation: %w", err)
	}
	for i := range items {
		if !items[i].MonitorEnabled {
			continue
		}
		if err := d.syncDestinationCron(ctx, &items[i]); err != nil {
			return err
		}
	}
	return nil
}

func (d *Dispatcher) manageSavedDestinations(ctx context.Context, p *DestinationParams, skipDeadbolt bool) (*DestinationResult, error) {
	if ctx == nil || d.jobStore == nil {
		return nil, errors.New("context and job store are required")
	}
	switch strings.ToLower(strings.TrimSpace(p.Action)) {
	case "list":
		return d.destinationListResult(ctx, "list", nil)
	case "save":
		return d.saveDestination(ctx, p)
	case "delete":
		return d.deleteDestination(ctx, p.ID)
	case "run":
		dst, err := d.resolveDestination(ctx, p.ID, p.Name)
		if err != nil {
			return nil, err
		}
		out, err := d.runSavedDestination(ctx, dst, p.Style, "saved_destination", skipDeadbolt)
		if err != nil {
			return nil, err
		}
		return &DestinationResult{Action: "run", Item: dst, Outcome: out}, nil
	default:
		return nil, fmt.Errorf("%w: unsupported destination action %q", ErrInvalidArgs, p.Action)
	}
}

func (d *Dispatcher) destinationListResult(ctx context.Context, action string, item *store.SavedDestination) (*DestinationResult, error) {
	items, err := d.jobStore.ListDestinations(ctx)
	if err != nil {
		return nil, fmt.Errorf("list destinations: %w", err)
	}
	return &DestinationResult{Action: action, Item: item, Items: items}, nil
}

func (d *Dispatcher) saveDestination(ctx context.Context, p *DestinationParams) (*DestinationResult, error) {
	d.destMu.Lock()
	defer d.destMu.Unlock()

	var dst, prev store.SavedDestination
	hadExisting := false
	if id := strings.TrimSpace(p.ID); id != "" {
		existing, err := d.jobStore.GetDestination(ctx, id)
		switch {
		case err == nil:
			dst, prev, hadExisting = *existing, *existing, true
		case !errors.Is(err, store.ErrNotFound):
			return nil, fmt.Errorf("load destination %q: %w", id, err)
		default:
			dst.ID = id
		}
	}
	applyDestinationUpdates(&dst, p)
	if dst.Name == "" || dst.Target == "" {
		return nil, fmt.Errorf("%w: parameters \"name\" and \"target\" are required", ErrInvalidArgs)
	}
	if err := validateDestinationTarget(ctx, d.guard, dst.Target); err != nil {
		return nil, err
	}
	check, err := validateDestinationCheck(dst.DefaultCheck)
	if err != nil {
		return nil, err
	}
	dst.DefaultCheck, dst.MonitorSchedule = check, firstNonEmpty(dst.MonitorSchedule, defaultMonitorSchedule)
	if err := d.jobStore.SaveDestination(ctx, &dst); err != nil {
		return nil, fmt.Errorf("save destination: %w", err)
	}
	if syncErr := d.syncDestinationCron(ctx, &dst); syncErr != nil {
		rbCtx := context.WithoutCancel(ctx)
		if hadExisting {
			_ = d.jobStore.SaveDestination(rbCtx, &prev)
		} else {
			_, _ = d.jobStore.DeleteDestination(rbCtx, dst.ID)
		}
		return nil, syncErr
	}
	return d.destinationListResult(ctx, "save", &dst)
}

func (d *Dispatcher) deleteDestination(ctx context.Context, id string) (*DestinationResult, error) {
	trimmedID := strings.TrimSpace(id)
	if trimmedID == "" {
		return nil, fmt.Errorf("%w: parameter \"id\" is required", ErrInvalidArgs)
	}
	d.destMu.Lock()
	defer d.destMu.Unlock()

	existing, err := d.jobStore.GetDestination(ctx, trimmedID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, fmt.Errorf("destination %q: %w", trimmedID, store.ErrNotFound)
		}
		return nil, fmt.Errorf("load destination %q: %w", trimmedID, err)
	}
	if err := d.syncDestinationCron(ctx, &store.SavedDestination{ID: trimmedID, MonitorEnabled: false}); err != nil {
		return nil, err
	}
	deleted, err := d.jobStore.DeleteDestination(ctx, trimmedID)
	if err != nil {
		if existing.MonitorEnabled {
			_ = d.syncDestinationCron(context.WithoutCancel(ctx), existing)
		}
		return nil, fmt.Errorf("delete destination %q: %w", trimmedID, err)
	}
	if !deleted {
		if existing.MonitorEnabled {
			_ = d.syncDestinationCron(context.WithoutCancel(ctx), existing)
		}
		return nil, fmt.Errorf("destination %q: %w", trimmedID, store.ErrNotFound)
	}
	return d.destinationListResult(ctx, "delete", nil)
}

func (d *Dispatcher) resolveDestination(ctx context.Context, id, name string) (*store.SavedDestination, error) {
	if cleanID := strings.TrimSpace(id); cleanID != "" {
		dst, err := d.jobStore.GetDestination(ctx, cleanID)
		if err != nil {
			return nil, fmt.Errorf("load destination %q: %w", cleanID, err)
		}
		return dst, nil
	}
	cleanName := strings.TrimSpace(name)
	if cleanName == "" {
		return nil, fmt.Errorf("%w: parameter \"id\" or \"name\" is required", ErrInvalidArgs)
	}
	items, err := d.jobStore.ListDestinations(ctx)
	if err != nil {
		return nil, fmt.Errorf("list destinations: %w", err)
	}
	var exact, fold []store.SavedDestination
	for i := range items {
		if items[i].Name == cleanName {
			exact = append(exact, items[i])
		} else if strings.EqualFold(items[i].Name, cleanName) {
			fold = append(fold, items[i])
		}
	}
	matches := exact
	if len(matches) == 0 {
		matches = fold
	}
	if len(matches) == 0 {
		return nil, fmt.Errorf("destination %q: %w", cleanName, store.ErrNotFound)
	}
	if len(matches) > 1 {
		return nil, fmt.Errorf("%w: multiple destinations named %q; specify id", ErrInvalidArgs, cleanName)
	}
	return &matches[0], nil
}

func (d *Dispatcher) runSavedDestination(ctx context.Context, dst *store.SavedDestination, style, source string, skipDeadbolt bool) (*Outcome, error) {
	args := map[string]any{"target": dst.Target}
	if dst.MAC != "" {
		args["mac"] = dst.MAC
	}
	return d.Dispatch(ctx, Request{
		Tool: dst.DefaultCheck, Args: args, Style: style,
		Source: firstNonEmpty(source, "saved_destination"), SkipDeadbolt: skipDeadbolt,
	})
}

func (d *Dispatcher) syncDestinationCron(ctx context.Context, dst *store.SavedDestination) error {
	sched := d.Scheduler()
	if sched == nil {
		return nil
	}
	cronKey := destCronPrefix + dst.ID
	listRes, err := sched.ManageWatchlist(ctx, cronmon.ManageParams{Action: "list"})
	if err != nil {
		return fmt.Errorf("list cron watchlist: %w", err)
	}
	exists := false
	for i := range listRes.Items {
		if listRes.Items[i].Key == cronKey {
			exists = true
			break
		}
	}
	if !dst.MonitorEnabled {
		if !exists {
			return nil
		}
		if _, err := sched.ManageWatchlist(ctx, cronmon.ManageParams{Action: "remove", Key: cronKey}); err != nil {
			return fmt.Errorf("remove destination cron %q: %w", cronKey, err)
		}
		return nil
	}
	action, args := "add", map[string]any(nil)
	if exists {
		action, args = "update", map[string]any{}
	}
	if dst.MAC != "" {
		args = map[string]any{"mac": dst.MAC}
	}
	enabled := true
	if _, err := sched.ManageWatchlist(ctx, cronmon.ManageParams{
		Action: action, Key: cronKey, Schedule: firstNonEmpty(dst.MonitorSchedule, defaultMonitorSchedule),
		Tool: dst.DefaultCheck, Target: dst.Target, Args: args, Enabled: &enabled,
	}); err != nil {
		return fmt.Errorf("sync destination cron %q: %w", cronKey, err)
	}
	return nil
}

func applyDestinationUpdates(dst *store.SavedDestination, p *DestinationParams) {
	for _, pair := range []struct {
		src string
		dst *string
	}{
		{p.Name, &dst.Name},
		{p.Target, &dst.Target},
		{p.Category, &dst.Category},
		{p.MAC, &dst.MAC},
		{p.DefaultCheck, &dst.DefaultCheck},
		{p.MonitorSchedule, &dst.MonitorSchedule},
	} {
		if v := strings.TrimSpace(pair.src); v != "" {
			*pair.dst = v
		}
	}
	if p.ClearMAC {
		dst.MAC = ""
	}
	if p.Pinned != nil {
		dst.Pinned = *p.Pinned
	}
	if p.MonitorEnabled != nil {
		dst.MonitorEnabled = *p.MonitorEnabled
	}
	dst.Name, dst.Target, dst.MAC = strings.TrimSpace(dst.Name), strings.TrimSpace(dst.Target), strings.TrimSpace(dst.MAC)
}

func validateDestinationCheck(raw string) (string, error) {
	check := strings.ToLower(strings.TrimSpace(raw))
	if check == "" {
		return defaultDestCheckTool, nil
	}
	if _, ok := knownToolSet[check]; !ok {
		return "", fmt.Errorf("%w: unknown default_check %q", ErrInvalidArgs, raw)
	}
	if _, disallowed := disallowedDestChecks[check]; disallowed {
		return "", fmt.Errorf("%w: default_check %q is not permitted for saved destinations", ErrInvalidArgs, check)
	}
	return check, nil
}
