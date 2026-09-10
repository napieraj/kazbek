package sqlite

import (
	"context"
	"path/filepath"
	"testing"
)

// Verifies the reconnect minimal-write path: MarkOnline flips status + refreshes
// last_seen_at without rewriting identity columns.
func TestMarkOnlineAndClientGuard(t *testing.T) {
	dsn := filepath.Join(t.TempDir(), "mw.db")
	db, err := Open(context.Background(), Options{DSN: dsn, MaxOpenConns: 4, MaxIdleConns: 4})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()
	g := db.Gorm()
	g.Exec(`CREATE TABLE devices (id INTEGER PRIMARY KEY AUTOINCREMENT, ddns TEXT, mac TEXT, name TEXT DEFAULT '',
		description TEXT DEFAULT '', ip TEXT DEFAULT '', client TEXT DEFAULT '', device_group_id INTEGER,
		status TEXT, last_seen_at INTEGER)`)
	g.Exec(`INSERT INTO devices(ddns,mac,description,ip,client,status,last_seen_at)
		VALUES ('dev1','aabbcc','MacInfo','10.0.0.9','rtty-go','offline',100)`)

	repo := NewDeviceMetaRepo(g)
	ctx := context.Background()

	if err := repo.MarkOnline(ctx, "dev1"); err != nil {
		t.Fatalf("MarkOnline: %v", err)
	}
	var status, mac, desc, ip string
	var lastSeen int64
	g.Raw(`SELECT status,mac,description,ip,last_seen_at FROM devices WHERE ddns='dev1'`).
		Row().Scan(&status, &mac, &desc, &ip, &lastSeen)
	if status != "online" {
		t.Errorf("status=%q want online", status)
	}
	if lastSeen <= 100 {
		t.Errorf("last_seen_at not refreshed: %d", lastSeen)
	}
	// identity columns untouched
	if mac != "aabbcc" || desc != "MacInfo" || ip != "10.0.0.9" {
		t.Errorf("identity columns changed: mac=%q desc=%q ip=%q", mac, desc, ip)
	}

}

// SetClientIfUnset must be first-write-wins. The client type classifies a
// device's own sessions, so a device that can rewrite it picks its own
// classification — see DeviceMetaRepo.SetClientIfUnset and Device.ClientType.
//
// MUTATION CHECK (AGENTS.md rule 4): relax the WHERE clause in
// SetClientIfUnset to an unconditional UPDATE, or back to the previous
// `client <> ?` form, and the "reclassify" subtest below goes red. If it does
// not, the guard is dead and this test is not holding it down.
func TestSetClientIfUnsetIsFirstWriteWins(t *testing.T) {
	dsn := filepath.Join(t.TempDir(), "cli.db")
	db, err := Open(context.Background(), Options{DSN: dsn, MaxOpenConns: 4, MaxIdleConns: 4})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()
	g := db.Gorm()
	g.Exec(`CREATE TABLE devices (id INTEGER PRIMARY KEY AUTOINCREMENT, ddns TEXT, mac TEXT, name TEXT DEFAULT '',
		description TEXT DEFAULT '', ip TEXT DEFAULT '', client TEXT DEFAULT '', device_group_id INTEGER,
		status TEXT, last_seen_at INTEGER)`)
	// Two rows: one with no client recorded yet, one already enrolled.
	g.Exec(`INSERT INTO devices(ddns,mac,client,status,last_seen_at) VALUES ('fresh','aa','','offline',1)`)
	g.Exec(`INSERT INTO devices(ddns,mac,client,status,last_seen_at) VALUES ('known','bb','rtty-go','offline',1)`)

	repo := NewDeviceMetaRepo(g)
	ctx := context.Background()

	clientOf := func(ddns string) string {
		var c string
		g.Raw(`SELECT client FROM devices WHERE ddns=?`, ddns).Row().Scan(&c)
		return c
	}

	// First write on an unset row records the claim.
	if err := repo.SetClientIfUnset(ctx, "fresh", "rtty-go"); err != nil {
		t.Fatalf("SetClientIfUnset fresh: %v", err)
	}
	if got := clientOf("fresh"); got != "rtty-go" {
		t.Errorf("first write should record: client=%q want rtty-go", got)
	}

	// THE GUARD: a device claiming a different type must NOT reclassify itself.
	if err := repo.SetClientIfUnset(ctx, "known", "definitely-not-rtty-go"); err != nil {
		t.Fatalf("SetClientIfUnset known: %v", err)
	}
	if got := clientOf("known"); got != "rtty-go" {
		t.Errorf("device reclassified itself: client=%q want rtty-go (the enrolled value)", got)
	}

	// Re-asserting the same value is a no-op, not an error.
	if err := repo.SetClientIfUnset(ctx, "known", "rtty-go"); err != nil {
		t.Fatalf("SetClientIfUnset repeat: %v", err)
	}
	if got := clientOf("known"); got != "rtty-go" {
		t.Errorf("repeat claim changed the value: client=%q", got)
	}
}
