package server

import (
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"

	"rttys/internal/authz"
	"rttys/internal/store/sqlite"
)

// Resolving an authorization subject on the device-tunnel path.
//
// This is the prerequisite the capability model needs and did not have: before
// this, handleUserConnection bound a user to a device console with no principal
// in scope at all, and httpAuth returned a bool without ever resolving WHICH
// user was calling (see docs/modules/permissions-phase0.md §2).
//
// It is deliberately NOT principalFromCtx. That function is documented
// "best-effort ... Never blocks the calling path" and returns (0, "") when it
// cannot resolve anyone, which is correct for tagging an audit record and
// catastrophic for an authorization input: a caller treating its zero value as
// a subject would grant whatever the empty subject is granted. Reusing it here
// would be exactly the "unknown treated as a value" bug that D-013's test asks
// about. Two callers, two failure modes, two functions.

// AuthzSubject resolves the authenticated user as an authorization subject.
//
// FAIL CLOSED: ok is false whenever the subject cannot be established with
// certainty — no session store, no cookie, an unknown session, no user record.
// There is no "anonymous" or zero subject; callers must refuse rather than
// substitute one. Do NOT add a fallback return here.
func AuthzSubject(c *gin.Context) (authz.Subject, bool) {
	if c == nil || c.Request == nil || sessionStore == nil {
		return authz.Subject{}, false
	}
	sid, err := c.Cookie("sid")
	if err != nil {
		return authz.Subject{}, false
	}
	sid = strings.TrimSpace(sid)
	if sid == "" {
		return authz.Subject{}, false
	}
	sess, ok := sessionStore.Get(sid)
	if !ok {
		return authz.Subject{}, false
	}
	if sess.UserID == 0 {
		return authz.Subject{}, false
	}

	// The user must still exist. A session outliving its user is precisely the
	// case where a stale id would otherwise be treated as a live principal.
	cont := sqlite.TryContainer()
	if cont == nil || cont.UserSvc == nil {
		return authz.Subject{}, false
	}
	u, err := cont.UserSvc.FindByID(c.Request.Context(), sess.UserID)
	if err != nil || u == nil {
		return authz.Subject{}, false
	}

	return authz.User(subjectIDForUser(sess.UserID)), true
}

// subjectIDForUser renders a user id as a grant subject id. Grants are written
// against this string, so it must be stable for the life of the account —
// which is why it is the numeric id and not the username: usernames are
// editable, and a rename must not silently move someone's grants.
func subjectIDForUser(id int64) string {
	return "user:" + strconv.FormatInt(id, 10)
}
