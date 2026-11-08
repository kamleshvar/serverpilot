(function () {
  var root = document.documentElement;
  if (!root) return;

  root.classList.remove('no-js');
  root.classList.add('js');

  var reduceMotion = false;
  try {
    reduceMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  } catch (error) {
    reduceMotion = false;
  }

  var seenIntro = false;
  try {
    seenIntro = window.sessionStorage.getItem('serverpilot-intro-seen') === '1';
  } catch (error) {
    seenIntro = false;
  }

  var authenticated = root.getAttribute('data-authenticated') === 'true';
  var skipIntro = reduceMotion || seenIntro || authenticated;

  if (skipIntro) {
    root.classList.add('intro-skip');
    root.classList.remove('intro-active');
  } else {
    root.classList.add('intro-active');
  }

  window.setTimeout(function () {
    if (!window.__serverpilotLandingReady) {
      var items = document.querySelectorAll('.reveal');
      for (var i = 0; i < items.length; i += 1) {
        items[i].classList.add('is-visible');
      }
    }

    if (root.classList.contains('intro-skip')) return;

    root.classList.add('intro-skip');
    root.classList.remove('intro-active');

    try {
      window.sessionStorage.setItem('serverpilot-intro-seen', '1');
    } catch (error) {
      /* Storage can be unavailable in private or restricted contexts. */
    }

    var page = document.getElementById('page');
    if (page) page.removeAttribute('inert');

    var intro = document.querySelector('[data-intro]');
    if (intro) intro.setAttribute('aria-hidden', 'true');
  }, 7000);
})();
