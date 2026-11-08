(function () {
  'use strict';

  var INTRO_DURATION = 4400;
  var INTRO_SEEN_KEY = 'serverpilot-intro-seen';

  var root = document.documentElement;
  var intro = document.querySelector('[data-intro]');
  var page = document.getElementById('page');
  var skipButton = document.querySelector('[data-intro-skip]');
  var header = document.querySelector('[data-site-header]');
  var navToggle = document.querySelector('[data-nav-toggle]');
  var mobileMenu = document.querySelector('[data-mobile-menu]');
  var introTimer = null;
  var introFinished = false;
  var revealInitialized = false;
  var scrollTicking = false;

  function storeIntroSeen() {
    try {
      window.sessionStorage.setItem(INTRO_SEEN_KEY, '1');
    } catch (error) {
      /* Storage can be unavailable in private or restricted contexts. */
    }
  }

  function initReveals() {
    if (revealInitialized) return;
    revealInitialized = true;
    window.__serverpilotLandingReady = true;

    var items = Array.prototype.slice.call(document.querySelectorAll('.reveal'));
    if (!items.length) return;

    var reduceMotion = false;
    try {
      reduceMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    } catch (error) {
      reduceMotion = false;
    }

    if (reduceMotion || !('IntersectionObserver' in window)) {
      items.forEach(function (item) {
        item.classList.add('is-visible');
      });
      return;
    }

    var observer = new IntersectionObserver(
      function (entries) {
        entries.forEach(function (entry) {
          if (!entry.isIntersecting) return;
          entry.target.classList.add('is-visible');
          observer.unobserve(entry.target);
        });
      },
      { threshold: 0.12, rootMargin: '0px 0px -8% 0px' }
    );

    items.forEach(function (item) {
      observer.observe(item);
    });
  }

  function finishIntro(remember) {
    if (introFinished) return;
    introFinished = true;

    if (introTimer) {
      window.clearTimeout(introTimer);
      introTimer = null;
    }

    if (remember) storeIntroSeen();

    root.classList.add('intro-skip');
    root.classList.remove('intro-active');

    if (page) page.removeAttribute('inert');

    if (intro) {
      intro.setAttribute('aria-hidden', 'true');
      window.setTimeout(function () {
        intro.style.display = 'none';
      }, 60);
    }

    initReveals();
  }

  function startIntro() {
    if (!intro || root.classList.contains('intro-skip')) {
      initReveals();
      return;
    }

    if (page) page.setAttribute('inert', '');

    introTimer = window.setTimeout(function () {
      finishIntro(true);
    }, INTRO_DURATION);

    if (skipButton) {
      skipButton.addEventListener('click', function () {
        finishIntro(true);
      });
    }

    document.addEventListener('keydown', function (event) {
      if (event.key === 'Escape' && !introFinished) finishIntro(true);
    });
  }

  function setMobileMenu(open) {
    if (!navToggle || !mobileMenu) return;

    navToggle.setAttribute('aria-expanded', open ? 'true' : 'false');
    navToggle.setAttribute('aria-label', open ? 'Close navigation' : 'Open navigation');

    if (open) {
      mobileMenu.hidden = false;
      window.requestAnimationFrame(function () {
        mobileMenu.classList.add('is-open');
      });
    } else {
      mobileMenu.classList.remove('is-open');
      mobileMenu.hidden = true;
    }
  }

  function initMobileMenu() {
    if (!navToggle || !mobileMenu) return;

    navToggle.addEventListener('click', function () {
      setMobileMenu(navToggle.getAttribute('aria-expanded') !== 'true');
    });

    mobileMenu.querySelectorAll('a').forEach(function (link) {
      link.addEventListener('click', function () {
        setMobileMenu(false);
      });
    });

    document.addEventListener('click', function (event) {
      if (navToggle.getAttribute('aria-expanded') !== 'true') return;
      if (mobileMenu.contains(event.target) || navToggle.contains(event.target)) return;
      setMobileMenu(false);
    });

    document.addEventListener('keydown', function (event) {
      if (event.key === 'Escape') setMobileMenu(false);
    });

    window.addEventListener('resize', function () {
      if (window.innerWidth > 980) setMobileMenu(false);
    });
  }

  var navLinks = Array.prototype.slice.call(document.querySelectorAll('[data-nav-link]'));
  var spySections = [];

  navLinks.forEach(function (link) {
    var href = link.getAttribute('href');
    if (!href || href.charAt(0) !== '#') return;

    var section = document.querySelector(href);
    if (!section || spySections.indexOf(section) !== -1) return;
    spySections.push(section);
  });

  function updateActiveNav() {
    if (!spySections.length) return;

    var marker = window.scrollY + 140;
    var activeId = '';

    spySections.forEach(function (section) {
      var top = section.getBoundingClientRect().top + window.scrollY;
      if (top <= marker && top + section.offsetHeight > marker) {
        activeId = '#' + section.id;
      }
    });

    navLinks.forEach(function (link) {
      link.classList.toggle('is-active', link.getAttribute('href') === activeId);
    });
  }

  function updateHeader() {
    if (header) header.classList.toggle('is-scrolled', window.scrollY > 10);
    updateActiveNav();
  }

  function onScroll() {
    if (scrollTicking) return;
    scrollTicking = true;

    window.requestAnimationFrame(function () {
      updateHeader();
      scrollTicking = false;
    });
  }

  function initNavigation() {
    initMobileMenu();
    updateHeader();
    window.addEventListener('scroll', onScroll, { passive: true });
  }

  startIntro();
  initNavigation();
})();
