import React, { useEffect, useState } from 'react'
import { Outlet, NavLink } from 'react-router-dom'
import { apiFetch } from '../api.js'

const nav = [
  { to: '/dashboard',     icon: '📊', label: 'Dashboard' },
  { to: '/repositories',  icon: '📁', label: 'Repositories' },
  { to: '/scans',         icon: '🔍', label: 'Scans' },
  { to: '/setup',         icon: '⚙️',  label: 'Setup & Webhook' },
]

export default function Layout() {
  const [authorized, setAuthorized] = useState(false)
  const [checking, setChecking] = useState(true)
  const [apiKey, setApiKey] = useState('')
  const [error, setError] = useState('')

  useEffect(() => {
    const savedKey = sessionStorage.getItem('platform_api_key')
    if (!savedKey) {
      setChecking(false)
      return
    }

    apiFetch('/api/stats')
      .then(response => {
        if (response.ok) {
          setAuthorized(true)
        } else {
          sessionStorage.removeItem('platform_api_key')
          setError('Clé API invalide. Saisissez une clé valide.')
        }
      })
      .catch(() => setError("Impossible de joindre l'API. Vérifiez que la plateforme est démarrée."))
      .finally(() => setChecking(false))
  }, [])

  const signIn = async (event) => {
    event.preventDefault()
    setError('')
    try {
      const response = await fetch('/api/stats', {
        headers: { 'X-API-Key': apiKey.trim() }
      })
      if (!response.ok) throw new Error('Clé API invalide.')
      sessionStorage.setItem('platform_api_key', apiKey.trim())
      setAuthorized(true)
    } catch (err) {
      setError(err.message || "Impossible de joindre l'API.")
    }
  }

  if (checking) {
    return <div style={{ padding: 32, color: 'var(--text2)' }}>Vérification de la clé API…</div>
  }

  if (!authorized) {
    return (
      <div style={{ minHeight: '100vh', display: 'grid', placeItems: 'center', background: 'var(--bg)' }}>
        <form onSubmit={signIn} style={{
          width: 'min(420px, calc(100% - 32px))', padding: 28,
          background: 'var(--bg2)', border: '1px solid var(--border)', borderRadius: 'var(--radius)'
        }}>
          <h1 style={{ fontSize: 20, marginBottom: 8 }}>ZeroTrustOps</h1>
          <p style={{ color: 'var(--text2)', fontSize: 13, marginBottom: 18 }}>
            Saisissez la valeur de <code>PLATFORM_API_KEY</code> dans votre fichier <code>.env</code>.
          </p>
          <input
            type="password"
            autoComplete="current-password"
            value={apiKey}
            onChange={event => setApiKey(event.target.value)}
            placeholder="Clé API"
            required
            style={{ width: '100%', marginBottom: 12 }}
          />
          {error && <p role="alert" style={{ color: 'var(--red)', fontSize: 13, marginBottom: 12 }}>{error}</p>}
          <button type="submit" style={{
            width: '100%', background: 'var(--accent)', color: '#fff',
            borderRadius: 'var(--radius)', padding: '9px 16px', fontWeight: 600
          }}>Se connecter</button>
        </form>
      </div>
    )
  }

  return (
    <div style={{ display: 'flex', minHeight: '100vh' }}>

      {/* Sidebar */}
      <aside style={{
        width: 220, background: 'var(--bg2)',
        borderRight: '1px solid var(--border)',
        display: 'flex', flexDirection: 'column',
        position: 'fixed', top: 0, bottom: 0, left: 0,
        zIndex: 100
      }}>
        {/* Logo */}
        <div style={{ padding: '20px 16px', borderBottom: '1px solid var(--border)' }}>
          <div style={{ fontSize: 16, fontWeight: 800, color: 'var(--text)' }}>
            🔒 ZeroTrustOps
          </div>
          <div style={{ fontSize: 11, color: 'var(--text2)', marginTop: 2 }}>
            Security Enforcement Platform
          </div>
        </div>

        {/* Nav */}
        <nav style={{ flex: 1, padding: '8px 0' }}>
          {nav.map(item => (
            <NavLink key={item.to} to={item.to} style={({ isActive }) => ({
              display: 'flex', alignItems: 'center', gap: 10,
              padding: '10px 16px', fontSize: 13, fontWeight: 500,
              color: isActive ? 'var(--text)' : 'var(--text2)',
              background: isActive ? 'var(--bg3)' : 'transparent',
              borderLeft: isActive ? '2px solid var(--accent)' : '2px solid transparent',
              transition: 'all 0.15s',
              textDecoration: 'none'
            })}>
              <span>{item.icon}</span>
              <span>{item.label}</span>
            </NavLink>
          ))}
        </nav>

        {/* Footer */}
        <div style={{ padding: 16, borderTop: '1px solid var(--border)',
                      fontSize: 11, color: 'var(--text2)' }}>
          <div>v1.0.0 · Roudayna Kouka</div>
          <button onClick={() => {
            sessionStorage.removeItem('platform_api_key')
            setAuthorized(false)
            setApiKey('')
          }} style={{ marginTop: 8, color: 'var(--text2)', background: 'transparent', fontSize: 11 }}>
            Se déconnecter
          </button>
        </div>
      </aside>

      {/* Main content */}
      <main style={{ marginLeft: 220, flex: 1, minHeight: '100vh' }}>
        <Outlet />
      </main>
    </div>
  )
}
