package sqlite

import (
    "context"
    "errors"
    "fmt"
    "rttys/model"

    "gorm.io/gorm"

    "rttys/utils"
)

type DeviceMetaRepo struct {
    db *gorm.DB
}

func NewDeviceMetaRepo(db *gorm.DB) *DeviceMetaRepo {
    return &DeviceMetaRepo{db: db}
}

func (r *DeviceMetaRepo) SaveOrUpdate(ctx context.Context, deviceID, mac, description, ip string) error {
    if r.db == nil {
        return fmt.Errorf("gorm db is nil")
    }

    normMac := utils.NormalizeMac(mac)
    return r.db.WithContext(ctx).Exec(
        `INSERT INTO devices (ddns, mac, description, ip, status, last_seen_at)
         VALUES (?, ?, ?, ?, 'online', unixepoch())
         ON CONFLICT(ddns) DO UPDATE SET
           mac=excluded.mac,
           description=excluded.description,
           ip=excluded.ip,
           status='online',
           last_seen_at=unixepoch()`,
        deviceID, normMac, description, ip,
    ).Error
}

// MarkOnline flips a known device back online and refreshes last_seen without
// rewriting its (unchanged) identity columns. Used on reconnect to avoid the
// write amplification of a full upsert during reconnect storms.
func (r *DeviceMetaRepo) MarkOnline(ctx context.Context, deviceID string) error {
    if r.db == nil {
        return fmt.Errorf("gorm db is nil")
    }
    return r.db.WithContext(ctx).Exec(
        `UPDATE devices SET status='online', last_seen_at=unixepoch() WHERE ddns=?`,
        deviceID,
    ).Error
}

// SetClientIfUnset records a device's client type ONCE and never changes it.
//
// The client type is a claim the device makes about itself, and it is consumed
// server-side to classify the device's own sessions. If a device could rewrite
// it at will, the device would be choosing how the server classifies it — so
// this is deliberately first-write-wins, matching UpdateDescriptionIfEmpty
// below. A later claim of a different type is ignored by this UPDATE; the
// caller is expected to notice the divergence and log it, because a device
// changing its self-description is a signal worth keeping.
//
// Do NOT relax this to an unconditional UPDATE. The previous version wrote
// whenever the value differed, which made the field device-controlled for the
// life of the device.
//
// This is an interim owner. Once provisioning (roadmap item 3) establishes
// device facts at enrolment, the client type should be set by that ceremony
// and this becomes a fallback for pre-enrolment records.
func (r *DeviceMetaRepo) SetClientIfUnset(ctx context.Context, deviceID, client string) error {
    if r.db == nil {
        return fmt.Errorf("gorm db is nil")
    }
    return r.db.WithContext(ctx).Exec(
        `UPDATE devices SET client=? WHERE ddns=? AND (client IS NULL OR client='')`,
        client, deviceID,
    ).Error
}

func (r *DeviceMetaRepo) UpdateDescriptionIfEmpty(ctx context.Context, deviceID, description string) error {
    if r.db == nil {
        return fmt.Errorf("gorm db is nil")
    }
    return r.db.WithContext(ctx).Exec(
        `UPDATE devices SET description=? WHERE ddns=? AND (description IS NULL OR description='')`,
        description, deviceID,
    ).Error
}

func (r *DeviceMetaRepo) GetByDeviceID(ctx context.Context, deviceID string) (*model.DeviceMeta, error) {
    var meta model.DeviceMeta
    err := r.db.WithContext(ctx).Where("ddns = ?", deviceID).First(&meta).Error
    if errors.Is(err, gorm.ErrRecordNotFound) {
        return nil, nil
    }
    return &meta, err
}

func (r *DeviceMetaRepo) GetByMac(ctx context.Context, mac string) (*model.DeviceMeta, error) {
    normMac := utils.NormalizeMac(mac)

    var meta model.DeviceMeta
    err := r.db.WithContext(ctx).Where("mac = ?", normMac).First(&meta).Error
    if errors.Is(err, gorm.ErrRecordNotFound) {
        return nil, nil
    }
    return &meta, err
}

func (r *DeviceMetaRepo) List(ctx context.Context, keyword string) ([]model.DeviceMeta, error) {
    var list []model.DeviceMeta

    q := r.db.WithContext(ctx).Model(&model.DeviceMeta{})
    if keyword != "" {
        normMac := utils.NormalizeMac(keyword)
        likeDesc := "%" + keyword + "%"
        q = q.Where("ddns = ? OR mac = ? OR description LIKE ? OR ip = ?", keyword, normMac, likeDesc, keyword)
    }

    if err := q.Order("id ASC").Find(&list).Error; err != nil {
        return nil, err
    }
    return list, nil
}

func (r *DeviceMetaRepo) ListByDeviceIDs(ctx context.Context, deviceIDs []string) ([]model.DeviceMeta, error) {
    if len(deviceIDs) == 0 {
        return []model.DeviceMeta{}, nil
    }

    var list []model.DeviceMeta
    if err := r.db.WithContext(ctx).
        Where("ddns IN ?", deviceIDs).
        Find(&list).Error; err != nil {
        return nil, err
    }
    return list, nil
}

func (r *DeviceMetaRepo) DeleteByDeviceID(ctx context.Context, deviceID string) error {
    res := r.db.WithContext(ctx).Where("ddns = ?", deviceID).Delete(&model.DeviceMeta{})
    if res.Error != nil {
        return res.Error
    }
    if res.RowsAffected == 0 {
        return gorm.ErrRecordNotFound
    }
    return nil
}

func (r *DeviceMetaRepo) MarkOffline(ctx context.Context, deviceID string) error {
    return r.db.WithContext(ctx).Exec(
        `UPDATE devices SET status='offline' WHERE ddns=?`,
        deviceID,
    ).Error
}
