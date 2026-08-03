import { NavLink, Outlet } from 'react-router-dom'
import { useAuth } from '../auth/AuthContext'
import { NotificationBell } from './NotificationBell'
import { SearchBar } from './SearchBar'

const NAV_ITEMS = [
  { to: '/', label: 'Dashboard', end: true },
  { to: '/events', label: 'Events', end: false },
  { to: '/incidents', label: 'Incidents', end: false },
  { to: '/assets', label: 'Assets', end: false },
]

export function Layout() {
  const { user, logout } = useAuth()

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100">
      <header className="border-b border-slate-800 px-6 py-3 flex items-center justify-between gap-4">
        <div className="flex items-center gap-8">
          <span className="font-semibold text-indigo-400 shrink-0">CyberSentinel AI</span>
          <nav className="flex gap-1">
            {NAV_ITEMS.map((item) => (
              <NavLink
                key={item.to}
                to={item.to}
                end={item.end}
                className={({ isActive }) =>
                  `px-3 py-1.5 rounded-lg text-sm font-medium transition ${
                    isActive ? 'bg-slate-800 text-white' : 'text-slate-400 hover:text-slate-100'
                  }`
                }
              >
                {item.label}
              </NavLink>
            ))}
          </nav>
        </div>
        <div className="flex items-center gap-4">
          <SearchBar />
          <NotificationBell />
          <div className="flex items-center gap-3 text-sm shrink-0">
            <span className="text-slate-400">{user?.email}</span>
            <span className="px-2 py-0.5 rounded bg-slate-800 text-xs uppercase tracking-wide text-indigo-300">
              {user?.role}
            </span>
            <button onClick={logout} className="text-slate-400 hover:text-white transition">
              Log out
            </button>
          </div>
        </div>
      </header>
      <main className="max-w-6xl mx-auto px-6 py-6">
        <Outlet />
      </main>
    </div>
  )
}
