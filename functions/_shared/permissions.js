// functions/_shared/permissions.js
//
// Server-side source of truth for role permissions. This mirrors the
// PERMISSIONS map in index.html — but the copy in index.html is now used
// only to enable/disable buttons in the UI. The real enforcement happens
// here, on every request, because the browser can never be trusted to
// honestly report or enforce its own permissions.

const REPRESENTATIVE_PERMISSIONS = { VIEW: true, CREATE: false, EDIT: false, ASSIGN: false, APPROVE: true, VERIFY: true, CLOSE: true, SENSITIVE_DATA_ACCESS: true, scope: "ALL" };

export const PERMISSIONS = {
  REPRESENTATIVE_MP:        { ...REPRESENTATIVE_PERMISSIONS },
  REPRESENTATIVE_MLA:       { ...REPRESENTATIVE_PERMISSIONS },
  REPRESENTATIVE_MAYOR:     { ...REPRESENTATIVE_PERMISSIONS },
  REPRESENTATIVE_SARPANCH:  { ...REPRESENTATIVE_PERMISSIONS },
  REPRESENTATIVE_OTHER:     { ...REPRESENTATIVE_PERMISSIONS },
  CHIEF_OF_STAFF:     { VIEW: true, CREATE: true,  EDIT: true,  ASSIGN: true,  APPROVE: true,  VERIFY: true,  CLOSE: true,  SENSITIVE_DATA_ACCESS: true,  scope: "ALL" },
  OFFICE_ADMIN:       { VIEW: true, CREATE: true,  EDIT: true,  ASSIGN: true,  APPROVE: false, VERIFY: false, CLOSE: false, SENSITIVE_DATA_ACCESS: true,  scope: "ALL" },
  CONSTITUENCY_TEAM:  { VIEW: true, CREATE: true,  EDIT: true,  ASSIGN: true,  APPROVE: false, VERIFY: false, CLOSE: false, SENSITIVE_DATA_ACCESS: true,  scope: "ALL" },
  FIELD_TEAM:         { VIEW: true, CREATE: true,  EDIT: true,  ASSIGN: false, APPROVE: false, VERIFY: false, CLOSE: false, SENSITIVE_DATA_ACCESS: true,  scope: "OWN_ASSIGNED" },
  RESEARCH_TEAM:      { VIEW: true, CREATE: false, EDIT: false, ASSIGN: false, APPROVE: false, VERIFY: false, CLOSE: false, SENSITIVE_DATA_ACCESS: false, scope: "ALL" },
};

export function hasPermission(role, action) {
  const perms = PERMISSIONS[role];
  if (!perms || !(action in perms)) return false;
  return perms[action] === true;
}

// ---------------------------------------------------------------------
// Office records (Projects, Documents, Commitments) — added alongside
// grievances. These use a simpler view/manage split than grievances'
// multi-action model: every role that can VIEW grievances (hasPermission
// with "VIEW" — true for all roles today) can also view these, but only
// the roles that actually run the office day-to-day can create, edit, or
// mark them complete. Field team and research team stay read-only here
// even though FIELD_TEAM can create grievances — running a road project
// or logging a government order isn't part of that role's job, so this
// is intentionally a separate permission concept from grievance CREATE.
// ---------------------------------------------------------------------
export const OFFICE_RECORD_MANAGERS = new Set(["OFFICE_ADMIN", "CHIEF_OF_STAFF", "CONSTITUENCY_TEAM"]);

export function canManageOfficeRecords(role) {
  return OFFICE_RECORD_MANAGERS.has(role);
}
