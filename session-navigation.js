(() => {
  let revision = 0;
  async function refresh() {
    const current = ++revision;
    let links = [];
    let signedIn = false;
    try {
      const response = await fetch('/api/auth/navigation', { credentials: 'include', cache: 'no-store' });
      if (response.ok) {
        const data = await response.json();
        links = data.links || [];
        signedIn = data.signedIn === true;
      }
    } catch { /* Navigation stays unavailable when the session cannot be verified. */ }
    if (current !== revision) return;
    const signOut = document.getElementById('lfp-signout');
    if (signOut) signOut.style.display = signedIn ? 'inline-block' : 'none';
    document.getElementById('session-navigation')?.remove();
    if (!links.length) return;
    const bar = document.createElement('nav');
    bar.id = 'session-navigation';
    bar.setAttribute('aria-label', 'Account tools');
    bar.style.cssText = 'position:relative;z-index:110;display:flex;justify-content:flex-end;gap:12px;flex-wrap:wrap;padding:8px 20px;background:#14243b;border-bottom:1px solid #e8a82055;';
    for (const item of links) {
      if (typeof item.href !== 'string' || !item.href.startsWith('/') || item.href.startsWith('//')) continue;
      const link = document.createElement('a');
      link.href = item.href;
      link.textContent = item.label;
      link.style.cssText = 'display:inline-flex;align-items:center;justify-content:center;min-height:44px;padding:10px 18px;border-radius:8px;background:#e8a820;color:#080e20;font:600 14px Arial,sans-serif;text-decoration:none;';
      bar.append(link);
    }
    if (bar.childElementCount) document.body.prepend(bar);
  }
  document.addEventListener('click', event => {
    if (event.target.closest?.('#lfp-signout, .logout-btn')) {
      try { sessionStorage.removeItem('lfp_user'); sessionStorage.removeItem('lfp_token'); } catch {}
      ++revision;
      document.getElementById('session-navigation')?.remove();
    }
  }, true);
  window.addEventListener('lfp:session-changed', refresh);
  window.addEventListener('pageshow', refresh);
  window.addEventListener('focus', refresh);
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', refresh, { once: true });
  else refresh();
})();
