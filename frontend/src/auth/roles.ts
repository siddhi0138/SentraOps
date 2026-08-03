import type { Role } from '../api/types'

// Owner/Admin/SOC Manager/Analyst can all take write actions (approve,
// configure, comment, upload); Executive/Auditor are read-only everywhere.
const OPERATIONAL_ROLES: Role[] = ['owner', 'admin', 'soc_manager', 'analyst']
// Owner/Admin only - user management, connector/integration config, API keys.
const ADMIN_ROLES: Role[] = ['owner', 'admin']

export function canAct(role: Role | undefined): boolean {
  return !!role && OPERATIONAL_ROLES.includes(role)
}

export function isAdminRole(role: Role | undefined): boolean {
  return !!role && ADMIN_ROLES.includes(role)
}
