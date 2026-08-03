import {
  Activity,
  BarChart3,
  BookOpen,
  Bot,
  Building2,
  ChevronsUpDown,
  Compass,
  LayoutDashboard,
  LogOut,
  Menu,
  Moon,
  Radar,
  Search,
  Settings,
  ShieldAlert,
  Sun,
} from 'lucide-react'
import { useEffect, type ComponentType, type CSSProperties } from 'react'
import { NavLink, Outlet, useLocation } from 'react-router-dom'
import { useAuth } from '../auth/AuthContext'
import { canAct as roleCanAct } from '../auth/roles'
import { useTheme } from '../theme/ThemeContext'
import { hasSeenTour, useAppTour } from './AppTour'
import { NotificationBell } from './NotificationBell'
import { SearchBar } from './SearchBar'
import {
  Sidebar,
  SidebarContent,
  SidebarFooter,
  SidebarGroup,
  SidebarGroupContent,
  SidebarHeader,
  SidebarInset,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
  SidebarProvider,
  SidebarTrigger,
  useSidebar,
} from '@/components/ui/sidebar'
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger } from '@/components/ui/dropdown-menu'
import { Badge } from '@/components/ui/badge'
import { Separator } from '@/components/ui/separator'

interface NavItem {
  to: string
  label: string
  icon: ComponentType<{ className?: string }>
  end?: boolean
  // Every route this item's section owns, so the sidebar stays highlighted
  // while you're on any tab within it (e.g. /assets should still light up
  // "Investigate", not just its landing route /events).
  matches: string[]
  // Stable selector for AppTour to anchor a step to, independent of label
  // text (which the tour copy also changes over time).
  tourId: string
}

// Seven destinations, not eighteen - each one that used to be its own
// sidebar entry is now a tab inside one of these (see SectionLayout).
const NAV_ITEMS: NavItem[] = [
  { to: '/', label: 'Dashboard', icon: LayoutDashboard, end: true, matches: ['/'], tourId: 'dashboard' },
  { to: '/command-center', label: 'Command Center', icon: Radar, matches: ['/command-center'], tourId: 'command-center' },
  {
    to: '/events',
    label: 'Investigate',
    icon: Search,
    matches: ['/events', '/incidents', '/assets', '/attack-graph', '/digital-twin'],
    tourId: 'investigate',
  },
  {
    to: '/ai-team',
    label: 'AI Team',
    icon: Bot,
    matches: ['/ai-team', '/ai-analyst', '/ai-observability', '/learning', '/marketplace'],
    tourId: 'ai-team',
  },
  { to: '/threat-intel', label: 'Threat Intel', icon: ShieldAlert, matches: ['/threat-intel', '/predictive'], tourId: 'threat-intel' },
  { to: '/executive', label: 'Reports', icon: BarChart3, matches: ['/executive', '/compliance'], tourId: 'reports' },
  { to: '/integrations', label: 'Settings', icon: Settings, matches: ['/integrations', '/admin'], tourId: 'settings' },
]

function activeItem(pathname: string): NavItem | undefined {
  return NAV_ITEMS.find((item) =>
    item.matches.some((prefix) => (prefix === '/' ? pathname === '/' : pathname.startsWith(prefix)))
  )
}

// First 4 of the 7 sections + a "More" button that opens the full drawer -
// a real mobile-first bottom tab bar (thumb-reachable, fixed to viewport),
// not just the desktop sidebar squeezed onto a phone. Rendered inside
// SidebarProvider so it can reuse the same drawer the sidebar trigger opens.
const MOBILE_TAB_ITEMS = NAV_ITEMS.slice(0, 4)

function MobileTabBar({ current }: { current: NavItem | undefined }) {
  const { setOpenMobile } = useSidebar()
  const moreActive = current && !MOBILE_TAB_ITEMS.some((item) => item.to === current.to)

  return (
    <nav className="fixed inset-x-0 bottom-0 z-40 flex h-14 items-stretch border-t border-border bg-background/95 backdrop-blur sm:hidden">
      {MOBILE_TAB_ITEMS.map((item) => {
        const isActive = current?.to === item.to
        return (
          <NavLink
            key={item.to}
            to={item.to}
            end={item.end}
            className={`flex flex-1 flex-col items-center justify-center gap-0.5 text-[10px] ${
              isActive ? 'text-primary' : 'text-muted-foreground'
            }`}
          >
            <item.icon className={`h-5 w-5 ${isActive ? 'text-glow' : ''}`} />
            {item.label}
          </NavLink>
        )
      })}
      <button
        onClick={() => setOpenMobile(true)}
        className={`flex flex-1 flex-col items-center justify-center gap-0.5 text-[10px] ${
          moreActive ? 'text-primary' : 'text-muted-foreground'
        }`}
      >
        <Menu className={`h-5 w-5 ${moreActive ? 'text-glow' : ''}`} />
        More
      </button>
    </nav>
  )
}

export function Layout() {
  const { user, logout } = useAuth()
  const { theme, toggleTheme } = useTheme()
  const location = useLocation()
  const current = activeItem(location.pathname)
  const canAct = roleCanAct(user?.role)
  const { startTour } = useAppTour(canAct)

  // Layout mounts once per session (React Router keeps it mounted across
  // route changes, only <Outlet/> swaps) - fires once for a genuinely new
  // browser, not on every navigation. Small delay so the tour doesn't
  // measure elements before the first real layout/paint settles.
  useEffect(() => {
    if (hasSeenTour()) return
    const timer = setTimeout(() => startTour(), 800)
    return () => clearTimeout(timer)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  return (
    <SidebarProvider
      style={{ '--sidebar-width-icon': '3.75rem' } as CSSProperties}
    >
      <Sidebar collapsible="icon">
        <SidebarHeader className="px-3 py-3">
          <div data-tour="brand" className="flex items-center gap-2 px-1">
            <div className="relative flex h-7 w-7 shrink-0 items-center justify-center rounded-md bg-primary/15 text-primary glow-primary">
              <Activity className="h-4 w-4 text-glow" />
              <span className="absolute -bottom-0.5 -right-0.5 h-1.5 w-1.5 rounded-full bg-severity-low pulse-dot" />
            </div>
            <div className="flex flex-col leading-none group-data-[collapsible=icon]:hidden">
              <span className="font-mono text-sm font-semibold text-foreground">SentraOps</span>
              <span className="text-[11px] uppercase tracking-[0.14em] text-muted-foreground">AI Security Ops</span>
            </div>
          </div>
        </SidebarHeader>
        <SidebarContent>
          <SidebarGroup>
            <SidebarGroupContent>
              <SidebarMenu>
                {NAV_ITEMS.map((item) => {
                  const isActive = current?.to === item.to
                  return (
                    <SidebarMenuItem key={item.to}>
                      <SidebarMenuButton
                        isActive={isActive}
                        tooltip={item.label}
                        size="lg"
                        className="rounded-none border-l-2 border-transparent pl-3 text-[15px] gap-3 data-[active=true]:border-primary data-[active=true]:bg-primary/10 data-[active=true]:text-primary data-[active=true]:text-glow group-data-[collapsible=icon]:size-11! group-data-[collapsible=icon]:p-2!"
                        render={
                          <NavLink to={item.to} end={item.end} data-tour={`nav-${item.tourId}`}>
                            <item.icon className="h-5 w-5 shrink-0" />
                            <span className="truncate group-data-[collapsible=icon]:hidden">{item.label}</span>
                          </NavLink>
                        }
                      />
                    </SidebarMenuItem>
                  )
                })}
              </SidebarMenu>
            </SidebarGroupContent>
          </SidebarGroup>
        </SidebarContent>
        <SidebarFooter className="px-3 pb-3">
          <DropdownMenu>
            <DropdownMenuTrigger
              render={
                <button
                  data-tour="user-menu"
                  className="flex w-full items-center gap-2 rounded-md border border-sidebar-border bg-sidebar-accent/40 px-2 py-2 text-left text-sm hover:bg-sidebar-accent transition group-data-[collapsible=icon]:justify-center"
                />
              }
            >
              <div className="flex h-6 w-6 shrink-0 items-center justify-center rounded-full bg-primary/20 text-[11px] font-medium text-primary">
                {user?.email?.[0]?.toUpperCase() ?? '?'}
              </div>
              <div className="flex min-w-0 flex-1 flex-col leading-tight group-data-[collapsible=icon]:hidden">
                <span className="truncate text-xs text-foreground">{user?.email}</span>
                <span className="text-[10px] uppercase tracking-wide text-muted-foreground">{user?.role}</span>
              </div>
              <ChevronsUpDown className="h-3.5 w-3.5 shrink-0 text-muted-foreground group-data-[collapsible=icon]:hidden" />
            </DropdownMenuTrigger>
            <DropdownMenuContent align="start" side="top" className="w-56">
              <div className="px-2 py-1.5 text-xs text-muted-foreground">
                <div className="flex items-center gap-1.5 text-foreground">
                  <Building2 className="h-3.5 w-3.5" />
                  {user?.organization_name}
                </div>
                <div className="mt-0.5 font-mono text-[10px]">invite code: {user?.organization_slug}</div>
              </div>
              <DropdownMenuItem onClick={toggleTheme}>
                {theme === 'dark' ? <Sun className="h-4 w-4" /> : <Moon className="h-4 w-4" />}
                {theme === 'dark' ? 'Light mode' : 'Dark mode'}
              </DropdownMenuItem>
              <DropdownMenuItem onClick={startTour}>
                <Compass className="h-4 w-4" />
                Take a tour
              </DropdownMenuItem>
              <DropdownMenuItem variant="destructive" onClick={logout}>
                <LogOut className="h-4 w-4" />
                Log out
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
        </SidebarFooter>
      </Sidebar>

      <SidebarInset>
        <header className="sticky top-0 z-30 flex h-14 shrink-0 items-center justify-between gap-4 border-b border-border bg-background/60 px-4 backdrop-blur">
          <div className="flex min-w-0 items-center gap-3">
            <SidebarTrigger className="-ml-1" />
            <Separator orientation="vertical" className="h-4" />
            <h1 className="truncate text-sm font-medium text-foreground">{current?.label ?? 'SentraOps'}</h1>
            <Badge variant="outline" className="hidden items-center gap-1.5 font-mono text-[10px] text-muted-foreground sm:inline-flex">
              <span className="h-1.5 w-1.5 rounded-full bg-severity-low pulse-dot" />
              <BookOpen className="h-3 w-3" />
              live
            </Badge>
          </div>
          <div className="flex shrink-0 items-center gap-3">
            <div data-tour="search" className="hidden sm:block">
              <SearchBar />
            </div>
            <div data-tour="notifications">
              <NotificationBell />
            </div>
          </div>
        </header>
        <main className="relative flex-1 overflow-y-auto px-4 py-4 pb-20 sm:px-6 sm:py-6 sm:pb-6">
          <div className="pointer-events-none fixed inset-0 -z-10 grid-bg opacity-30" />
          <div className="mx-auto max-w-6xl">
            <Outlet />
          </div>
        </main>
        <footer className="sticky bottom-0 z-30 hidden h-9 shrink-0 items-center justify-between gap-3 border-t border-border bg-background/60 px-4 text-[11px] text-muted-foreground backdrop-blur sm:flex">
          <span className="truncate">
            {user?.organization_name} <span className="hidden sm:inline">&middot; {user?.role}</span>
          </span>
          <span className="flex shrink-0 items-center gap-1.5 font-mono">
            <span className="h-1.5 w-1.5 rounded-full bg-severity-low pulse-dot" />
            SentraOps
          </span>
        </footer>
      </SidebarInset>
      <MobileTabBar current={current} />
    </SidebarProvider>
  )
}
