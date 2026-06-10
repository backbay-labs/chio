import { afterEach, vi } from 'vitest'

;(globalThis as typeof globalThis & { IS_REACT_ACT_ENVIRONMENT: boolean }).IS_REACT_ACT_ENVIRONMENT =
  true

afterEach(() => {
  document.body.innerHTML = ''
  sessionStorage.clear()
  vi.restoreAllMocks()
  window.history.replaceState({}, '', '/')
})
