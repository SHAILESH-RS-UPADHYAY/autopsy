try {
  const t = localStorage.getItem('ax-theme');
  if (t) document.documentElement.dataset.theme = t;
} catch {
  /* storage blocked: follow the system */
}
