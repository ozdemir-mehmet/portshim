/* Theme toggle for the PortShim site — one implementation, loaded by every page.
 *
 *   index.html        <script src="assets/theme.js"></script>
 *   pages/*.html      <script src="../assets/theme.js"></script>
 *
 * The tag sits at the end of <body>, where the inline copy of this code used to be. That is a
 * deliberate position with a cost: an inline copy ran while the page was being parsed, before the
 * first paint, whereas a fetched file runs once it has arrived — so on a slow first load a visitor
 * sees the theme in the markup and this script corrects it a moment later. Moving the tag into
 * <head> would remove that moment by making the fetch block the first paint instead. Applying the
 * choice before the first paint needs a small inline snippet in every page, which is the
 * duplication this issue removed; it is recorded here as a limit rather than left implied.
 *
 * One file is also one point of failure: if this asset is missing or blocked, every page keeps its
 * markup theme and the button does nothing. This path is classified as shipping, so the release
 * gate's condition 2 fails a tree that does not carry it — that is the whole protection against a
 * rename or a deletion reaching the public site.
 *
 * Two more limits, recorded rather than left to be discovered. A theme chosen here is not carried
 * into a visitor's other open tabs: nothing listens for the storage event, so another tab keeps the
 * theme it was loaded with until it is reloaded. And this path records the theme it resolved, which
 * on a first visit is the operating system's preference — a later change to that preference is
 * therefore not picked up, because as far as this script can tell the visitor has chosen.
 *
 * Until issue #51 each page carried its own inline copy. Eight of them used the
 * key below; the two pages added last, dependencies.html and wireless.html, were
 * written against 'ps-theme' — so they ignored the theme set anywhere else on the
 * site, and the two of them tracked each other because they shared that private
 * key. There is now one place this key can be wrong.
 *
 * The read of the old key is a one-time migration for a browser that holds it: it
 * is adopted only if no choice exists under the real key, then removed, so the
 * site ends up with a single key whatever a visitor did before.
 */
(function () {
  // A page can end up loading this file twice — one duplicated tag, one merged block. Two
  // evaluations would add two click listeners, and two listeners flip the theme twice per click, so
  // the button would stop changing anything. The first evaluation wins; the second does nothing.
  if (window.__portshimThemeLoaded) { return; }
  window.__portshimThemeLoaded = true;

  var KEY = 'portshim-theme';
  var OLD_KEY = 'ps-theme';

  function read(key) {
    try { return localStorage.getItem(key); } catch (e) { return null; }
  }
  function write(key, value) {
    try { localStorage.setItem(key, value); } catch (e) { /* storage unavailable */ }
  }
  function forget(key) {
    try { localStorage.removeItem(key); } catch (e) { /* storage unavailable */ }
  }
  // A value that is neither theme matches no CSS rule, so it is ignored rather than written
  // through: the page would keep its markup theme while the button claimed the other one, and the
  // value would be re-applied on every visit. The guard runs nineteen such values under each key,
  // including 'DARK', 'auto' and 'light '.
  function usable(value) {
    return value === 'light' || value === 'dark' ? value : null;
  }

  var toggle = document.getElementById('themeToggle');
  var saved = usable(read(KEY));

  if (!saved) {
    // The key the two broken pages wrote. Adopted once, then removed below.
    var previous = usable(read(OLD_KEY));
    if (previous) { saved = previous; }
  }

  function setTheme(theme) {
    document.documentElement.setAttribute('data-theme', theme);
    if (toggle) { toggle.textContent = theme === 'dark' ? '🌙' : '☀️'; }
    write(KEY, theme);
  }

  if (saved) {
    setTheme(saved);
  } else if (window.matchMedia && window.matchMedia('(prefers-color-scheme: light)').matches) {
    setTheme('light');
  } else {
    setTheme('dark');
  }

  if (read(OLD_KEY) !== null) { forget(OLD_KEY); }

  if (toggle) {
    toggle.addEventListener('click', function () {
      var current = document.documentElement.getAttribute('data-theme');
      setTheme(current === 'light' ? 'dark' : 'light');
    });
  }
})();
