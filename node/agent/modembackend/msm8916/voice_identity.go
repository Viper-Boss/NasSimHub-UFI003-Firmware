package msm8916

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	"github.com/godbus/dbus/v5"
	"github.com/human-agent65535/nassimhub-node/proto"
)

// MM object indices restart at zero. Include both boot and bus lifetimes and
// the unique service owner so a reboot, D-Bus restart, or MM restart cannot
// resurrect old history, leases, command receipts, or media sessions.
func modemCallEpoch(boot, bus, owner string) string {
	d := sha256.Sum256([]byte(strings.TrimSpace(boot) + "\x00" + bus + "\x00" + owner))
	return hex.EncodeToString(d[:16])
}

func (b *Backend) callLifetime(ctx context.Context) (string, string, error) {
	if b.options.CallEpoch != nil {
		epoch, err := b.options.CallEpoch(ctx)
		if _, _, ok := proto.ParseMMCallID("mm-" + epoch + "-0"); !ok && err == nil {
			err = fmt.Errorf("invalid injected modem lifetime")
		}
		return epoch, modemManagerService, err
	}
	// Existing injected transports describe legacy MM fixtures. Production
	// never takes this branch and never accepts an unscoped control ID.
	if b.options.Run != nil || b.options.RunBusctl != nil {
		return "", modemManagerService, nil
	}
	conn, err := activeBus(ctx)
	if err != nil {
		return "", "", err
	}
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil || strings.TrimSpace(string(boot)) == "" {
		return "", "", fmt.Errorf("cannot read boot identity: %w", err)
	}
	var bus, owner string
	if err = conn.BusObject().CallWithContext(ctx, "org.freedesktop.DBus.GetId", dbus.FlagNoAutoStart).Store(&bus); err != nil {
		return "", "", err
	}
	if err = conn.BusObject().CallWithContext(ctx, "org.freedesktop.DBus.GetNameOwner", dbus.FlagNoAutoStart, modemManagerService).Store(&owner); err != nil {
		return "", "", err
	}
	if bus == "" || !strings.HasPrefix(owner, ":") {
		return "", "", fmt.Errorf("invalid modem service owner")
	}
	return modemCallEpoch(string(boot), bus, owner), owner, nil
}

func scopeCallID(epoch, id string) string {
	if epoch == "" {
		return id
	}
	return "mm-" + epoch + "-" + strings.TrimPrefix(id, "mm-")
}

func (b *Backend) resolveCallID(ctx context.Context, op, id string) (string, string, error) {
	epoch, index, ok := proto.ParseMMCallID(id)
	if !ok {
		return "", "", proto.InvalidArgument(op, "invalid call id")
	}
	current, service, err := b.callLifetime(ctx)
	if err != nil {
		return "", "", proto.Unavailable(op, "cannot identify modem lifetime", err)
	}
	if epoch != current {
		return "", "", proto.NotFound(op, "call belongs to a previous modem lifetime")
	}
	// Use the unique owner as the D-Bus destination. A service restart after
	// validation cannot redirect the command to a new call with the same index.
	return callPathPrefix + index, service, nil
}
