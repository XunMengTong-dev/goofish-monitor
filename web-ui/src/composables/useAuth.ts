import { ref, computed } from 'vue'
import { useRouter } from 'vue-router'
import { wsService } from '@/services/websocket'

// Global State
const username = ref<string | null>(localStorage.getItem('auth_username'))
const isLoggedIn = ref(false)
let sessionCheckPromise: Promise<boolean> | null = null

export function useAuth() {
  const router = useRouter()

  const isAuthenticated = computed(() => isLoggedIn.value)

  function applyAuthenticatedSession(user: string) {
    username.value = user
    isLoggedIn.value = true

    localStorage.setItem('auth_username', user)

    // 启动 WebSocket 连接
    wsService.start()
  }

  function clearLocalSession() {
    username.value = null
    isLoggedIn.value = false
    localStorage.removeItem('auth_username')
  }

  async function logout() {
    clearLocalSession()

    // 停止 WebSocket 连接
    wsService.stop()

    try {
      await fetch('/auth/logout', {
        method: 'POST',
        credentials: 'same-origin',
      })
    } catch {
      // 本地状态仍需清除；即使网络错误也返回登录页。
    }

    // Redirect to login if using router
    if (router) {
      router.push('/login')
    } else {
      window.location.href = '/login'
    }
  }

  async function ensureSession(force = false): Promise<boolean> {
    if (isLoggedIn.value && !force) {
      return true
    }
    if (sessionCheckPromise) {
      return sessionCheckPromise
    }

    sessionCheckPromise = (async () => {
      try {
        const response = await fetch('/auth/session', {
          credentials: 'same-origin',
        })
        if (!response.ok) {
          clearLocalSession()
          return false
        }

        const data = await response.json()
        if (!data?.authenticated || !data?.username) {
          clearLocalSession()
          return false
        }

        applyAuthenticatedSession(data.username)
        return true
      } catch {
        clearLocalSession()
        return false
      } finally {
        sessionCheckPromise = null
      }
    })()

    return sessionCheckPromise
  }

  async function login(user: string, pass: string): Promise<boolean> {
    try {
      const response = await fetch('/auth/status', {
        method: 'POST',
        credentials: 'same-origin',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ username: user, password: pass }),
      })

      if (response.ok) {
        const data = await response.json().catch(() => ({}))
        applyAuthenticatedSession(data.username || user)
        return true
      } else {
        return false
      }
    } catch (e) {
      console.error('Login error', e)
      return false
    }
  }

  return {
    username,
    isAuthenticated,
    ensureSession,
    login,
    logout
  }
}
