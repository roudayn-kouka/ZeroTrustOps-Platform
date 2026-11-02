export function apiFetch(url, options = {}) {
  const headers = new Headers(options.headers || {})
  const apiKey = sessionStorage.getItem('platform_api_key')
  if (apiKey) headers.set('X-API-Key', apiKey)
  return fetch(url, { ...options, headers })
}
