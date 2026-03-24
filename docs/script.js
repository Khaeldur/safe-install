// Smooth scroll for anchor links
document.querySelectorAll('a[href^="#"]').forEach(function(anchor) {
  anchor.addEventListener('click', function(e) {
    var target = document.querySelector(this.getAttribute('href'));
    if (target) {
      e.preventDefault();
      target.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
  });
});

// Scroll-triggered fade-in animations
var observer = new IntersectionObserver(function(entries) {
  entries.forEach(function(entry) {
    if (entry.isIntersecting) {
      entry.target.classList.add('visible');
    }
  });
}, { threshold: 0.1, rootMargin: '0px 0px -50px 0px' });

document.querySelectorAll('.fade-in').forEach(function(el) {
  observer.observe(el);
});

// Install tabs
document.querySelectorAll('.install-tab').forEach(function(tab) {
  tab.addEventListener('click', function() {
    document.querySelectorAll('.install-tab').forEach(function(t) { t.classList.remove('active'); });
    document.querySelectorAll('.install-panel').forEach(function(p) { p.classList.remove('active'); });
    this.classList.add('active');
    document.getElementById('tab-' + this.dataset.tab).classList.add('active');
  });
});

// Copy to clipboard
document.querySelectorAll('.copy-btn').forEach(function(btn) {
  btn.addEventListener('click', function() {
    var text = this.dataset.copy;
    navigator.clipboard.writeText(text).then(function() {
      btn.textContent = 'Copied!';
      btn.classList.add('copied');
      setTimeout(function() {
        btn.textContent = 'Copy';
        btn.classList.remove('copied');
      }, 2000);
    });
  });
});

// Terminal demo animation
var demoLines = [
  { text: '$ safe-install audit reqeusts', type: 'command' },
  { text: '', type: 'blank' },
  { text: '  TYPOSQUAT DETECTED', type: 'error' },
  { text: '  "reqeusts" is similar to "requests" (distance: 2)', type: 'warn' },
  { text: '  Did you mean: requests (97M downloads/month)?', type: 'muted' },
  { text: '  Aborting. Use --force to override.', type: 'error' },
  { text: '', type: 'blank' },
  { text: '$ safe-install install flask --dry-run', type: 'command' },
  { text: '', type: 'blank' },
  { text: '  [1/8] Resolving dependency tree...', type: 'muted' },
  { text: '    flask 3.0.0 + 6 dependencies', type: 'muted' },
  { text: '  [2/8] Typosquat check............. PASS', type: 'success' },
  { text: '  [3/8] Threat intelligence lookup... PASS', type: 'success' },
  { text: '  [4/8] Source code scan............ PASS', type: 'success' },
  { text: '  [5/8] Binary analysis............. PASS', type: 'success' },
  { text: '  [6/8] Hash verification........... PASS', type: 'success' },
  { text: '  [7/8] Docker sandbox ready........ PASS', type: 'success' },
  { text: '  [8/8] Network monitor armed....... PASS', type: 'success' },
  { text: '', type: 'blank' },
  { text: '  All 8 checks passed. Safe to install.', type: 'success' },
  { text: '  Dry run complete. No packages were installed.', type: 'muted' },
];

var demoStarted = false;

function runDemo() {
  if (demoStarted) return;
  demoStarted = true;

  var body = document.getElementById('demo-body');
  body.innerHTML = '';

  var lineIndex = 0;
  var charIndex = 0;
  var currentLineEl = null;

  function typeNextChar() {
    if (lineIndex >= demoLines.length) {
      // add blinking cursor at end
      var cursor = document.createElement('span');
      cursor.className = 'cursor-blink';
      body.appendChild(cursor);
      // restart after pause
      setTimeout(function() {
        demoStarted = false;
      }, 6000);
      return;
    }

    var line = demoLines[lineIndex];

    if (!currentLineEl) {
      currentLineEl = document.createElement('div');
      currentLineEl.className = 'demo-line visible';
      body.appendChild(currentLineEl);
    }

    if (line.type === 'blank') {
      currentLineEl.innerHTML = '&nbsp;';
      lineIndex++;
      currentLineEl = null;
      setTimeout(typeNextChar, 100);
      return;
    }

    if (line.type === 'command') {
      // type character by character
      if (charIndex === 0) {
        currentLineEl.innerHTML = '<span class="prompt">$ </span>';
      }
      var cmdText = line.text.substring(2); // remove "$ "
      if (charIndex < cmdText.length) {
        currentLineEl.innerHTML = '<span class="prompt">$ </span>' + escapeHtml(cmdText.substring(0, charIndex + 1)) + '<span class="cursor-blink"></span>';
        charIndex++;
        setTimeout(typeNextChar, 30 + Math.random() * 40);
        return;
      }
      // done typing command
      currentLineEl.innerHTML = '<span class="prompt">$ </span>' + escapeHtml(cmdText);
      charIndex = 0;
      lineIndex++;
      currentLineEl = null;
      setTimeout(typeNextChar, 400);
      return;
    }

    // output lines appear instantly with a delay
    var cls = line.type;
    currentLineEl.innerHTML = '<span class="' + cls + '">' + escapeHtml(line.text) + '</span>';
    lineIndex++;
    currentLineEl = null;
    setTimeout(typeNextChar, 80);
  }

  setTimeout(typeNextChar, 500);
}

function escapeHtml(str) {
  return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

// Start demo when visible
var demoObserver = new IntersectionObserver(function(entries) {
  entries.forEach(function(entry) {
    if (entry.isIntersecting) {
      runDemo();
    }
  });
}, { threshold: 0.3 });

var demoEl = document.getElementById('demo-terminal');
if (demoEl) {
  demoObserver.observe(demoEl);
}

// Nav background on scroll
var nav = document.querySelector('.nav');
window.addEventListener('scroll', function() {
  if (window.scrollY > 50) {
    nav.style.borderBottomColor = 'var(--border)';
  } else {
    nav.style.borderBottomColor = 'transparent';
  }
});
