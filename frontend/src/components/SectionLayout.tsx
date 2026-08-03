import { NavLink, Outlet } from 'react-router-dom'
import { cn } from '@/lib/utils'

export interface SectionTab {
  to: string
  label: string
  end?: boolean
}

export function SectionLayout({ tabs }: { tabs: SectionTab[] }) {
  return (
    <div className="space-y-6">
      <div className="-mt-1 flex gap-1 overflow-x-auto border-b border-border">
        {tabs.map((tab) => (
          <NavLink
            key={tab.to}
            to={tab.to}
            end={tab.end}
            className={({ isActive }) =>
              cn(
                '-mb-px shrink-0 border-b-2 px-4 py-2.5 font-mono text-sm whitespace-nowrap transition',
                isActive
                  ? 'border-primary text-primary text-glow'
                  : 'border-transparent text-muted-foreground hover:text-foreground'
              )
            }
          >
            {tab.label}
          </NavLink>
        ))}
      </div>
      <Outlet />
    </div>
  )
}
