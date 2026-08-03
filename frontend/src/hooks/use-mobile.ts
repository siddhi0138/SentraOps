import * as React from "react"

const MOBILE_BREAKPOINT = 768

export function useIsMobile() {
  // Read synchronously on first render (not undefined-then-effect) - the
  // old version defaulted to "desktop" for one render on an actual phone,
  // briefly mounting the full desktop sidebar before switching to the Sheet
  // drawer, a visible layout flash on every load.
  const [isMobile, setIsMobile] = React.useState<boolean>(
    () => typeof window !== "undefined" && window.innerWidth < MOBILE_BREAKPOINT
  )

  React.useEffect(() => {
    const mql = window.matchMedia(`(max-width: ${MOBILE_BREAKPOINT - 1}px)`)
    const onChange = () => {
      setIsMobile(window.innerWidth < MOBILE_BREAKPOINT)
    }
    mql.addEventListener("change", onChange)
    return () => mql.removeEventListener("change", onChange)
  }, [])

  return isMobile
}
