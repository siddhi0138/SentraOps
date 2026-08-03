import {
  Activity,
  BarChart3,
  BookOpen,
  Bot,
  Building2,
  ChevronsUpDown,
  LayoutDashboard,
  LogOut,
  Radar,
  Search,
  Settings,
  ShieldAlert,
} from 'lucide-react'
import type { ComponentType } from 'react'
import { NavLink, Outlet, useLocation } from 'react-router-dom'
import { useAuth } from '../auth/AuthContext'
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
}

// Seven destinations, not eighteen - each one that used to be its own
// sidebar entry is now a tab inside one of these (see SectionLayout).
const NAV_ITEMS: NavItem[] = [
  { to: '/', label: 'Dashboard', icon: LayoutDashboard, end: true, matches: ['/'] },
  { to: '/command-center', label: 'Command Center', icon: Radar, matches: ['/command-center'] },
  {
    to: '/events',
    label: 'Investigate',
    icon: Search,
    matches: ['/events', '/incidents', '/assets', '/attack-graph', '/digital-twin'],
  },
  {
    to: '/ai-team',
    label: 'AI Team',
    icon: Bot,
    matches: ['/ai-team', '/ai-analyst', '/ai-observability', '/learning', '/marketplace'],
  },
  { to: '/threat-intel', label: 'Threat Intel', icon: ShieldAlert, matches: ['/threat-intel', '/predictive'] },
  { to: '/executive', label: 'Reports', icon: BarChart3, matches: ['/executive', '/compliance'] },
  { to: '/integrations', label: 'Settings', icon: Settings, matches: ['/integrations', '/admin'] },
]

function activeItem(pathname: string): NavItem | undefined {
  return NAV_ITEMS.find((item) =>
    item.matches.some((prefix) => (prefix === '/' ? pathname === '/' : pathname.startsWith(prefix)))
  )
}

export function Layout() {
  const { user, logout } = useAuth()
  const location = useLocation()
  const current = activeItem(location.pathname)

  return (
    <SidebarProvider>
      <Sidebar collapsible="icon">
        <SidebarHeader className="px-3 py-3">
          <div className="flex items-center gap-2 px-1">
            <div className="flex h-7 w-7 shrink-0 items-center justify-center rounded-md bg-primary/15 text-primary">
              <Activity className="h-4 w-4" />
            </div>
            <div className="flex flex-col leading-none group-data-[collapsible=icon]:hidden">
              <span className="font-mono text-sm font-semibold text-foreground">CyberSentinel</span>
              <span className="text-[11px] text-muted-foreground">AI Security Ops</span>
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
                        className="rounded-none border-l-2 border-transparent pl-2.5 data-[active=true]:border-primary data-[active=true]:bg-primary/10"
                        render={
                          <NavLink to={item.to} end={item.end}>
                            <item.icon className="h-4 w-4" />
                            <span>{item.label}</span>
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
                <button className="flex w-full items-center gap-2 rounded-md border border-sidebar-border bg-sidebar-accent/40 px-2 py-2 text-left text-sm hover:bg-sidebar-accent transition group-data-[collapsible=icon]:justify-center" />
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
              <DropdownMenuItem variant="destructive" onClick={logout}>
                <LogOut className="h-4 w-4" />
                Log out
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
        </SidebarFooter>
      </Sidebar>

      <SidebarInset>
        <header className="flex h-14 shrink-0 items-center justify-between gap-4 border-b border-border px-4">
          <div className="flex min-w-0 items-center gap-3">
            <SidebarTrigger className="-ml-1" />
            <Separator orientation="vertical" className="h-4" />
            <h1 className="truncate text-sm font-medium text-foreground">{current?.label ?? 'CyberSentinel AI'}</h1>
            <Badge variant="outline" className="hidden font-mono text-[10px] text-muted-foreground sm:inline-flex">
              <BookOpen className="h-3 w-3" />
              live
            </Badge>
          </div>
          <div className="flex items-center gap-3">
            <SearchBar />
            <NotificationBell />
          </div>
        </header>
        <main className="flex-1 overflow-y-auto px-6 py-6">
          <div className="mx-auto max-w-6xl">
            <Outlet />
          </div>
        </main>
      </SidebarInset>
    </SidebarProvider>
  )
}
