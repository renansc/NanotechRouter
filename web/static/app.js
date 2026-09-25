'use strict';
(() => {
  const sidebar = document.querySelector('.sidebar');
  const toggle = document.querySelector('.menu-toggle');
  const close = document.querySelector('.menu-close');
  const backdrop = document.querySelector('.menu-backdrop');
  const content = document.querySelector('.content');
  const header = document.querySelector('.mobile-header');
  const mobile = window.matchMedia('(max-width: 991.98px)');

  function setMenu(open, restoreFocus = true) {
    open = mobile.matches && open;
    document.body.classList.toggle('menu-open', open);
    toggle.setAttribute('aria-expanded', String(open));
    backdrop.hidden = !open;
    sidebar.inert = mobile.matches && !open;
    content.inert = open;
    header.inert = open;
    if (open) {
      sidebar.setAttribute('role', 'dialog');
      sidebar.setAttribute('aria-modal', 'true');
      requestAnimationFrame(() => {
        if (document.body.classList.contains('menu-open')) close.focus();
      });
    } else {
      sidebar.removeAttribute('role');
      sidebar.removeAttribute('aria-modal');
      if (restoreFocus && mobile.matches) toggle.focus();
    }
  }
  toggle.addEventListener('click', () => setMenu(true));
  close.addEventListener('click', () => setMenu(false));
  backdrop.addEventListener('click', () => setMenu(false));
  sidebar.querySelectorAll('nav a').forEach(link => link.addEventListener('click', () => setMenu(false, false)));
  document.addEventListener('keydown', event => {
    if (!document.body.classList.contains('menu-open')) return;
    if (event.key === 'Escape') {
      event.preventDefault();
      setMenu(false);
    } else if (event.key === 'Tab') {
      const focusable = [...sidebar.querySelectorAll('a[href], button, input:not([type="hidden"])')].filter(item => !item.disabled);
      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault(); last.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault(); first.focus();
      }
    }
  });
  mobile.addEventListener('change', () => setMenu(false, false));
  window.addEventListener('pageshow', () => setMenu(false, false));
  setMenu(false, false);

  // Preserve the existing forms and their IDs; only annotate cells for mobile layout.
  document.querySelectorAll('.content table').forEach(table => {
    if (!table.parentElement.classList.contains('table-responsive')) {
      const wrapper = document.createElement('div');
      wrapper.className = 'table-responsive';
      table.before(wrapper);
      wrapper.append(table);
    }
    const headers = [...table.querySelectorAll('thead th')];
    if (!headers.length) return;
    table.classList.add('table-mobile');
    // Explicit roles preserve table semantics when CSS changes the visual display.
    table.setAttribute('role', 'table');
    table.querySelectorAll('thead, tbody').forEach(group => group.setAttribute('role', 'rowgroup'));
    headers.forEach(th => { th.setAttribute('scope', 'col'); th.setAttribute('role', 'columnheader'); });
    table.querySelectorAll('tr').forEach(row => row.setAttribute('role', 'row'));
    table.querySelectorAll('tbody tr').forEach(row => {
      [...row.cells].forEach((cell, index) => {
        cell.setAttribute('role', 'cell');
        cell.dataset.label = headers[index]?.textContent.trim() || 'Ações';
        if (index === 0 || cell.colSpan > 1 || cell.querySelector('form, button, .btn')) cell.dataset.wide = '';
      });
    });
  });
})();
