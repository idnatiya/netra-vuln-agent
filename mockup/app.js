// Mockup behavior only: copy buttons, dialogs, tabs, and the mobile sidebar.

const COPY_ICON = '<svg class="size-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect width="14" height="14" x="8" y="8" rx="2"/><path d="M4 16c-1.1 0-2-.9-2-2V4c0-1.1.9-2 2-2h10c1.1 0 2 .9 2 2"/></svg>'
const CHECK_ICON = '<svg class="size-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20 6 9 17l-5-5"/></svg>'

document.addEventListener('DOMContentLoaded', () => {
  // <button data-copy="text"> or data-copy="" to copy the sibling <code>.
  document.querySelectorAll('[data-copy]').forEach((btn) => {
    btn.innerHTML = COPY_ICON
    btn.setAttribute('aria-label', 'Copy')
    btn.addEventListener('click', async () => {
      const text = btn.dataset.copy || btn.parentElement.querySelector('code').innerText
      try {
        await navigator.clipboard.writeText(text)
        btn.innerHTML = CHECK_ICON
        setTimeout(() => (btn.innerHTML = COPY_ICON), 1500)
      } catch {}
    })
  })

  // <button data-dialog="id"> opens <dialog id="id">; [data-close] inside closes it.
  document.querySelectorAll('[data-dialog]').forEach((btn) => {
    btn.addEventListener('click', () => document.getElementById(btn.dataset.dialog).showModal())
  })
  document.querySelectorAll('dialog').forEach((dlg) => {
    dlg.addEventListener('click', (e) => {
      if (e.target === dlg || e.target.closest('[data-close]')) dlg.close()
    })
  })

  // <div data-tabs> with buttons [data-tab="x"] and panels [data-panel="x"].
  document.querySelectorAll('[data-tabs]').forEach((group) => {
    const tabs = group.querySelectorAll('[data-tab]')
    const show = (name) => {
      tabs.forEach((t) => t.setAttribute('aria-selected', t.dataset.tab === name))
      group.querySelectorAll('[data-panel]').forEach((p) => (p.hidden = p.dataset.panel !== name))
    }
    tabs.forEach((t) => t.addEventListener('click', () => show(t.dataset.tab)))
    show(tabs[0].dataset.tab)
  })

  // [data-reveal="id"] un-hides #id (e.g. the enroll token after "Create").
  document.querySelectorAll('[data-reveal]').forEach((btn) => {
    btn.addEventListener('click', () => {
      document.getElementById(btn.dataset.reveal).hidden = false
      btn.closest('[data-step]')?.setAttribute('hidden', '')
    })
  })

  // login.html?error=1 shows the failed sign-in alert.
  if (new URLSearchParams(location.search).has('error')) {
    document.querySelector('[data-login-error]')?.removeAttribute('hidden')
  }

  // Mobile sidebar drawer: [data-sidebar-toggle] opens/closes, the backdrop closes.
  const sidebar = document.querySelector('[data-sidebar]')
  const backdrop = document.querySelector('[data-sidebar-backdrop]')
  const setSidebar = (open) => {
    sidebar?.classList.toggle('-translate-x-full', !open)
    backdrop?.toggleAttribute('hidden', !open)
  }
  document.querySelectorAll('[data-sidebar-toggle]').forEach((btn) => {
    btn.addEventListener('click', () => setSidebar(sidebar.classList.contains('-translate-x-full')))
  })
  backdrop?.addEventListener('click', () => setSidebar(false))
})
