package fixtures

import "rttys/internal/authz"

// The grant/subject/scope/constraint types were provisional here while the
// Phase 1 core did not exist. They are now owned by package authz, and these
// aliases keep the fixtures — and anything already written against them —
// compiling unchanged.
//
// New code should use rttys/internal/authz directly. These exist so promoting
// the types was not a rewrite of the test corpus.

type (
	SubjectKind      = authz.SubjectKind
	Subject          = authz.Subject
	Capability       = authz.Capability
	ScopeKind        = authz.ScopeKind
	Scope            = authz.Scope
	ConstraintKind   = authz.ConstraintKind
	Constraint       = authz.Constraint
	TimeOfDay        = authz.TimeOfDay
	TimeWindow       = authz.TimeWindow
	Effect           = authz.Effect
	Grant            = authz.Grant
	EnforcementPoint = authz.EnforcementPoint
	Request          = authz.Request
	Decision         = authz.Decision
	Engine           = authz.Engine
	EngineFunc       = authz.EngineFunc
	PortIndex        = authz.PortIndex
)

const (
	SubjectUser      = authz.SubjectUser
	SubjectUserGroup = authz.SubjectUserGroup
	PortNone         = authz.PortNone
	PortCount        = authz.PortCount

	CapView          = authz.CapView
	CapScreenshot    = authz.CapScreenshot
	CapScreenControl = authz.CapScreenControl
	CapHIDInput      = authz.CapHIDInput
	CapATXSoft       = authz.CapATXSoft
	CapATXHard       = authz.CapATXHard
	CapATXReset      = authz.CapATXReset
	CapMSDMount      = authz.CapMSDMount
	CapSerial        = authz.CapSerial
	CapPluginInstall = authz.CapPluginInstall
	CapISOMount      = authz.CapISOMount
	CapDeviceAdmin   = authz.CapDeviceAdmin

	ScopeDevice      = authz.ScopeDevice
	ScopeDeviceGroup = authz.ScopeDeviceGroup
	ScopePort        = authz.ScopePort

	ConstraintRequiresPresence = authz.ConstraintRequiresPresence
	ConstraintTimeWindow       = authz.ConstraintTimeWindow
	ConstraintFourEyes         = authz.ConstraintFourEyes

	EffectAllow = authz.EffectAllow
	EffectDeny  = authz.EffectDeny

	PointAPI    = authz.PointAPI
	PointStream = authz.PointStream
	PointTunnel = authz.PointTunnel
	PointHID    = authz.PointHID
)

var (
	User             = authz.User
	UserGroup        = authz.UserGroup
	DeviceScope      = authz.DeviceScope
	DeviceGroupScope = authz.DeviceGroupScope
	PortScope        = authz.PortScope
	RequiresPresence = authz.RequiresPresence
	WithinWindow     = authz.WithinWindow
	FourEyes         = authz.FourEyes
	WindowOpenAt     = authz.WindowOpenAt
	WindowClosedAt   = authz.WindowClosedAt
	Allowed          = authz.Allowed
	Denied           = authz.Denied
	AllCapabilities  = authz.AllCapabilities
)
