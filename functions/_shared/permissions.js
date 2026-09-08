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
