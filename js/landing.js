// ═══════════════════════════════════════════════════
// SENTINELX — landing page
// Digital rain, boot sequence, and a live terminal
// prompt. Launching redirects to app.html (the SPA).
// ═══════════════════════════════════════════════════

const REDUCED = matchMedia('(prefers-reduced-motion: reduce)').matches;
const APP_URL = 'app.html';

// ── Digital rain ───────────────────────────────────
// Classic column rain; characters near the pointer get
// highlighted in Kali blue so the backdrop reacts to you.
const rain = (() => {
    const canvas = document.getElementById('rain');
    const ctx = canvas.getContext('2d');
    const GLYPHS = 'アイウエオカキクケコサシスセソタチツテト0123456789ABCDEF<>/\\{}[]$#@%&*+=';
    const FONT = 15;
    let cols = 0, drops = [], W = 0, H = 0;
    let mx = -9999, my = -9999;

    function resize() {
        W = canvas.width = innerWidth;
        H = canvas.height = innerHeight;
        cols = Math.floor(W / FONT);
        drops = Array.from({ length: cols }, () => Math.random() * -H / FONT);
    }

    function frame() {
        ctx.fillStyle = 'rgba(0, 0, 0, 0.08)';
        ctx.fillRect(0, 0, W, H);
        ctx.font = FONT + 'px monospace';
        for (let i = 0; i < cols; i++) {
            const x = i * FONT;
            const y = drops[i] * FONT;
            const ch = GLYPHS[(Math.random() * GLYPHS.length) | 0];
            const nearMouse = Math.abs(x - mx) < 70 && Math.abs(y - my) < 70;
            if (nearMouse) {
                ctx.fillStyle = '#37a6ff';
            } else if (Math.random() < 0.04) {
                ctx.fillStyle = '#9dffb8';           // occasional bright head
            } else {
                ctx.fillStyle = 'rgba(32, 194, 80, 0.55)';
            }
            ctx.fillText(ch, x, y);
            if (y > H && Math.random() > 0.975) drops[i] = 0;
            drops[i] += nearMouse ? 1.6 : 1;         // rain accelerates under the cursor
        }
    }

    let last = 0;
    function loop(t) {
        if (t - last > 50) { frame(); last = t; }
        requestAnimationFrame(loop);
    }

    return {
        start() {
            if (REDUCED) return;
            resize();
            addEventListener('resize', resize);
            requestAnimationFrame(loop);
        },
        pointer(x, y) { mx = x; my = y; },
    };
})();

// ── Parallax: mouse + scroll ───────────────────────
// The dragon composes both inputs (mouse drift + scroll lag);
// hero layers scroll away at different speeds, and each
// section's giant ghost type drifts relative to the viewport.
const dragon = document.getElementById('dragon');
const heroTitle = document.querySelector('.glitch');
const heroTag = document.querySelector('.tagline');
const px = { mx: 0, my: 0, sy: 0 };

function paintDragon() {
    if (!dragon) return;
    dragon.style.transform =
        `translate(${(px.mx * 14).toFixed(1)}px, ${(px.my * 10 + px.sy * 0.45).toFixed(1)}px)` +
        ` rotate(${(px.mx * 1.6).toFixed(2)}deg)`;
}

addEventListener('pointermove', (e) => {
    rain.pointer(e.clientX, e.clientY);
    if (REDUCED) return;
    px.mx = (e.clientX / innerWidth - 0.5);
    px.my = (e.clientY / innerHeight - 0.5);
    paintDragon();
});

const parallaxBgs = () => document.querySelectorAll('.lsec-bg');
let scrollTick = false;
let lastSy = 0, vel = 0;
function parallaxFrame() {
    scrollTick = false;
    px.sy = scrollY;
    // Scroll velocity → the ghost type shears like a signal losing sync
    vel = vel * 0.6 + (px.sy - lastSy) * 0.4;
    lastSy = px.sy;
    const skew = Math.max(-9, Math.min(9, vel * 0.10));
    paintDragon();
    // Hero text scrolls away slower than the page → depth
    if (heroTitle) heroTitle.style.transform = `translateY(${(px.sy * 0.22).toFixed(1)}px)`;
    if (heroTag) heroTag.style.transform = `translateY(${(px.sy * 0.14).toFixed(1)}px)`;
    // Ghost type drifts against its section, keyed to viewport centre
    parallaxBgs().forEach((el) => {
        const r = el.parentElement.getBoundingClientRect();
        const mid = r.top + r.height / 2 - innerHeight / 2;
        el.style.transform =
            `translateY(${(mid * parseFloat(el.dataset.parallax || 0.2)).toFixed(1)}px)` +
            ` skewX(${skew.toFixed(2)}deg)`;
    });
    document.getElementById('scroll-cue')?.classList.toggle('hide', px.sy > 80);
    checkReveals();
    // Keep ticking until the shear settles back to rest
    if (Math.abs(vel) > 0.4 && !scrollTick) {
        scrollTick = true;
        requestAnimationFrame(parallaxFrame);
    }
}
if (!REDUCED) {
    addEventListener('scroll', () => {
        if (!scrollTick) { scrollTick = true; requestAnimationFrame(parallaxFrame); }
    }, { passive: true });
}

// ── Decode effect — text resolves out of random glyphs ──
const DECODE_GLYPHS = '!<>-_\\/[]{}—=+*^?#$%&';
function decode(el, dur = 600) {
    if (!el) return;
    const target = el.dataset.decodeTarget || el.textContent;
    el.dataset.decodeTarget = target;
    const t0 = performance.now();
    (function tick(t) {
        if (el.dataset.decodeTarget !== target) return;
        const p = Math.min(1, (t - t0) / dur);
        const shown = Math.floor(p * target.length);
        let s = target.slice(0, shown);
        for (let i = shown; i < target.length; i++) {
            s += target[i] === ' ' ? ' ' : DECODE_GLYPHS[(Math.random() * DECODE_GLYPHS.length) | 0];
        }
        el.textContent = s;
        if (p < 1) requestAnimationFrame(tick);
        else delete el.dataset.decodeTarget;
    })(t0);
}

// Reveal-on-scroll for section content — driven from the same scroll
// frame as the parallax (no IntersectionObserver: one less moving part)
let revealEls = [];
function watchReveals() {
    revealEls = [...document.querySelectorAll('.reveal:not(.in)')];
    if (REDUCED) {
        revealEls.forEach((el) => el.classList.add('in'));
        revealEls = [];
        return;
    }
    revealEls.forEach((el, i) => { el.style.animationDelay = (i % 4) * 80 + 'ms'; });
    checkReveals();
}
function checkReveals() {
    if (!revealEls.length) return;
    const limit = innerHeight * 0.92;
    revealEls = revealEls.filter((el) => {
        if (el.getBoundingClientRect().top < limit) {
            el.classList.add('in');
            // Text decrypts as the glitch settles
            const dec = el.querySelector?.('.dec, .ars-name') ||
                        (el.classList.contains('intel-chip') ? el : null);
            if (dec) {
                const delay = (parseFloat(el.style.animationDelay) || 0) + 150;
                setTimeout(() => decode(dec, 620), delay);
            }
            return false;
        }
        return true;
    });
}

// ── Terminal ───────────────────────────────────────
const out = document.getElementById('term-out');
const term = document.getElementById('term');
const inputLine = document.getElementById('term-input-line');
const typedEl = document.getElementById('term-typed');

const esc = (s) => s.replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));

function println(html = '') {
    const div = document.createElement('div');
    div.className = 'term-line';
    div.innerHTML = html;
    out.appendChild(div);
    term.scrollTop = term.scrollHeight;
}

// ── Boot sequence ──────────────────────────────────
// Every line states something true about the app; any
// keypress or click skips straight to the prompt.
const BOOT_LINES = [
    `<span class="dim">[</span><span class="ok"> ok </span><span class="dim">]</span> sentinelx console <span class="white">v2.1.0</span>`,
    `<span class="dim">[</span><span class="ok"> ok </span><span class="dim">]</span> 11 tool modules registered`,
    `<span class="dim">[</span><span class="ok"> ok </span><span class="dim">]</span> intel sources: <span class="blue">nvd · shodan internetdb · crt.sh · google doh</span>`,
    `<span class="dim">[</span><span class="ok"> ok </span><span class="dim">]</span> web crypto api: ${window.crypto && crypto.subtle ? '<span class="ok">available</span>' : '<span class="err">unavailable</span>'}`,
    `<span class="dim">[</span><span class="ok"> ok </span><span class="dim">]</span> access level: <span class="white">guest</span> — no account required`,
    `<span class="dim">ready. type</span> <span class="blue">help</span> <span class="dim">or press</span> <span class="white">enter</span><span class="dim">.</span>`,
];

let booting = true;
let bootTimer = null;

function finishBoot() {
    if (!booting) return;
    booting = false;
    clearTimeout(bootTimer);
    out.innerHTML = '';
    BOOT_LINES.forEach((l) => println(l));
    inputLine.style.display = '';
    document.getElementById('enter-btn').classList.add('show');
    document.getElementById('hint').classList.add('show');
    document.getElementById('scroll-cue')?.classList.add('show');
    term.scrollTop = term.scrollHeight;
}

function boot() {
    if (REDUCED) { finishBoot(); return; }
    let i = 0;
    (function next() {
        if (!booting) return;
        if (i >= BOOT_LINES.length) { finishBoot(); return; }
        println(BOOT_LINES[i]);
        i += 1;
        bootTimer = setTimeout(next, 260 + Math.random() * 240);
    })();
}

// ── Launch ─────────────────────────────────────────
function launch(hash = '') {
    document.body.classList.add('warp');
    setTimeout(() => { location.href = APP_URL + hash; }, REDUCED ? 0 : 520);
}
document.getElementById('enter-btn').addEventListener('click', () => launch());
document.querySelectorAll('[data-launch]').forEach((el) => el.addEventListener('click', () => launch()));

// ── Commands ───────────────────────────────────────
const TOOLS = [
    ['logs',      'log analyzer',      'extract & geolocate attackers from raw logs'],
    ['ips',       'ip lookup',         'geo, isp and exposed ports for any address'],
    ['dns',       'dns lookup',        'live records via google dns-over-https'],
    ['blocklist', 'blocklist manager', 'your blocklist — synced when signed in'],
    ['hash',      'hash generator',    'sha-256 / sha-1 / sha-512 + verification'],
    ['password',  'password checker',  'strength analysis + k-anonymous breach check'],
    ['ssl',       'ssl inspector',     'certificate transparency + subdomain discovery'],
    ['email',     'email security',    'spf / dkim / dmarc / dnssec audit'],
    ['cve',       'cve feed',          'live vulnerabilities from the nvd'],
    ['abuseipdb', 'abuseipdb',         'ip reputation scores & abuse reports'],
    ['typosquat', 'typosquat scanner', 'find live look-alike phishing domains'],
];

// Arsenal grid on the scroll page — one card per module
function renderArsenal() {
    const grid = document.getElementById('arsenal-grid');
    if (!grid) return;
    grid.innerHTML = TOOLS.map(([hash, name, desc]) => `
        <a class="ars-card reveal" href="${APP_URL}#${hash}">
            <span class="ars-hash">#${hash}</span>
            <div class="ars-name">${name}</div>
            <div class="ars-desc">${desc}</div>
        </a>`).join('');
}

const COMMANDS = {
    help() {
        println(`<span class="white">available commands</span>`);
        println(`  <span class="blue">enter</span>      launch the console`);
        println(`  <span class="blue">tools</span>      list every module (clickable)`);
        println(`  <span class="blue">neofetch</span>   show session info`);
        println(`  <span class="blue">whoami</span>     current operator`);
        println(`  <span class="blue">date</span>       current time`);
        println(`  <span class="blue">clear</span>      wipe the screen`);
        println(`  <span class="blue">exit</span>       …`);
    },
    enter: () => launch(),
    launch: () => launch(),
    start: () => launch(),
    open: () => launch(),
    tools() {
        TOOLS.forEach(([hash, name, desc]) =>
            println(`  <a href="${APP_URL}#${hash}">#${hash}</a> <span class="dim">— ${name}: ${desc}</span>`));
        println(`<span class="dim">click one, or</span> <span class="blue">enter</span> <span class="dim">for the dashboard.</span>`);
    },
    neofetch() {
        const ua = navigator.userAgent;
        const browser =
            ua.includes('Firefox') ? 'firefox' :
            ua.includes('Edg') ? 'edge' :
            ua.includes('Chrome') ? 'chrome' :
            ua.includes('Safari') ? 'safari' : 'unknown';
        const os =
            ua.includes('Mac') ? 'macos' :
            ua.includes('Win') ? 'windows' :
            ua.includes('Linux') ? 'linux' : 'unknown';
        println(`<span class="blue">guest</span><span class="dim">@</span><span class="blue">sentinelx</span>`);
        println(`<span class="dim">─────────────────</span>`);
        println(`<span class="white">host</span><span class="dim">:</span>     sentinelx soc console v2.1.0`);
        println(`<span class="white">client</span><span class="dim">:</span>   ${browser} on ${os}`);
        println(`<span class="white">viewport</span><span class="dim">:</span> ${innerWidth}×${innerHeight}`);
        println(`<span class="white">lang</span><span class="dim">:</span>     ${navigator.language}`);
        println(`<span class="white">tz</span><span class="dim">:</span>       ${Intl.DateTimeFormat().resolvedOptions().timeZone}`);
        println(`<span class="white">online</span><span class="dim">:</span>   ${navigator.onLine}`);
    },
    whoami: () => println('guest — sign in from the sidebar to sync your blocklist'),
    date: () => println(new Date().toString()),
    clear() { out.innerHTML = ''; },
    exit: () => println(`<span class="dim">there is no escape. type</span> <span class="blue">enter</span><span class="dim">.</span>`),
};

let buffer = '';

function runCommand(raw) {
    const cmd = raw.trim().toLowerCase();
    println(`<span class="ps1">guest@sentinelx:~$</span>${esc(raw)}`);
    if (cmd === '') { launch(); return; }
    if (cmd.startsWith('sudo')) { println(`<span class="err">permission denied:</span> nice try.`); return; }
    const fn = COMMANDS[cmd];
    if (fn) fn();
    else println(`<span class="err">command not found:</span> ${esc(cmd)} <span class="dim">— try</span> <span class="blue">help</span>`);
    term.scrollTop = term.scrollHeight;
}

// Type-anywhere input: the whole page is the terminal.
addEventListener('keydown', (e) => {
    if (e.metaKey || e.ctrlKey || e.altKey) return;
    if (booting) { finishBoot(); return; }

    if (e.key === 'Enter') {
        const raw = buffer;
        buffer = '';
        typedEl.textContent = '';
        runCommand(raw);
    } else if (e.key === 'Backspace') {
        buffer = buffer.slice(0, -1);
        typedEl.textContent = buffer;
    } else if (e.key.length === 1 && buffer.length < 60) {
        // Mid-command, space belongs to the terminal, not page scroll
        if (e.key === ' ' && buffer.length > 0) e.preventDefault();
        buffer += e.key;
        typedEl.textContent = buffer;
    }
});
addEventListener('click', () => { if (booting) finishBoot(); });

// ── Init ───────────────────────────────────────────
rain.start();
boot();
renderArsenal();
watchReveals();
if (!REDUCED) parallaxFrame();