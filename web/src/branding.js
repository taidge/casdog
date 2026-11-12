let active = 0;
let generation = 0;
const owned = new Set();
const roots = new Set();

function clearVisuals() {
    for (const node of owned) node.remove();
    for (const root of roots) {
        root.classList.remove('casdog-auth-root');
        root.removeAttribute('data-branding-application');
    }
    owned.clear();
    roots.clear();
}

export function beginBranding() {
    clearVisuals();
    active = ++generation;
    return active;
}

export function endBranding(token) {
    if (active !== token) return;
    clearVisuals();
    active = 0;
}

function style(css) {
    const element = document.createElement('style');
    element.dataset.applicationBranding = 'true';
    element.textContent = css;
    document.head.append(element);
    owned.add(element);
}

function cssRootSelectors(selector) {
    return selector.replace(/(^|[\s>+~,(])(?:html|body|:root)(?=$|[\s>+~,.#[:)])/g, '$1:where(:scope)');
}

function fontImports(css) {
    // The server accepts @import only for these font distributors. Preserve
    // approved font loading while keeping arbitrary imported stylesheets out
    // of the document. Constructed CSSStyleSheet would otherwise discard them.
    const prefixes = ['https://fonts.googleapis.com/', 'https://fonts.gstatic.com/',
        'https://cdn.jsdelivr.net/npm/@fontsource/', 'https://cdn.jsdelivr.net/npm/@fontsource-variable/'];
    for (const match of (css || '').matchAll(/@import\s+(?:url\(\s*)?(?:"([^"]*)"|'([^']*)')/gi)) {
        try {
            const url = new URL(match[1] || match[2]);
            if (url.username || url.password || !prefixes.some(prefix => url.href.startsWith(prefix))) continue;
            const link = document.createElement('link');
            link.rel = 'stylesheet';
            link.href = url.href;
            link.referrerPolicy = 'no-referrer';
            link.dataset.applicationBranding = 'font';
            document.head.append(link);
            owned.add(link);
        } catch {}
    }
}

// Browser CSS parsing preserves nested rules and selector lists. @scope limits
// rule subjects, including sibling selectors, to the authentication container.
// Older engines receive the basic theme without unscoped template CSS.
function scopedCss(css) {
    if (!css || typeof CSSScopeRule === 'undefined') return '';
    try {
        const sheet = new CSSStyleSheet();
        sheet.replaceSync(css);
        const render = rules => [...rules].map(rule => {
            if (rule.type === CSSRule.STYLE_RULE) {
                return `${cssRootSelectors(rule.selectorText)} {${rule.style.cssText}}`;
            }
            if (rule.type === CSSRule.MEDIA_RULE) return `@media ${rule.conditionText} {${render(rule.cssRules)}}`;
            if (rule.type === CSSRule.SUPPORTS_RULE) return `@supports ${rule.conditionText} {${render(rule.cssRules)}}`;
            // Font and keyframe definitions are allowed inside the scope;
            // imports and page/global mutation rules are not exported.
            if (rule.type === CSSRule.FONT_FACE_RULE || rule.type === CSSRule.KEYFRAMES_RULE) return rule.cssText;
            return '';
        }).join('\n');
        return `@scope (.casdog-auth-root) {${render(sheet.cssRules)}}`;
    } catch { return ''; }
}

function safeUrl(value) {
    if (typeof value !== 'string' || !value) return '';
    try {
        const url = new URL(value, window.location.href);
        if (url.protocol === 'https:' || (url.origin === location.origin && url.protocol === 'http:')) return url.href;
    } catch {}
    return '';
}

function htmlFrame(parent, title, html, footer) {
    if (typeof html !== 'string' || !html) return;
    const frame = document.createElement('iframe');
    frame.title = title;
    frame.setAttribute('sandbox', '');
    frame.setAttribute('referrerpolicy', 'no-referrer');
    frame.className = footer ? 'application-theme-footer' : 'application-theme-side';
    frame.style.cssText = `width:100%;border:0;min-height:${footer ? 80 : 160}px;display:block;`;
    frame.srcdoc = '<!doctype html><meta charset="utf-8"><meta name="referrer" content="no-referrer">'
        + '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; img-src https: data:; style-src \'unsafe-inline\' https:; font-src https:; form-action \'none\'; base-uri \'none\'">' + html;
    footer ? parent.append(frame) : parent.prepend(frame);
    owned.add(frame);
}

export function applyBranding(token, json) {
    if (token !== active) return;
    clearVisuals();
    let data;
    try { data = JSON.parse(json); } catch { return; }
    if (!data || typeof data !== 'object') return;
    const root = document.querySelector('.main');
    if (!root) return;
    root.classList.add('casdog-auth-root');
    root.dataset.brandingApplication = data.application || '';
    roots.add(root);
    const theme = data.themeData;
    let basic = '';
    if (theme?.isEnabled) {
        const color = theme.colorPrimary;
        if (typeof color === 'string' && /^#[0-9a-f]{3,8}$/i.test(color)) {
            basic += `.casdog-auth-root{--accent:${color};--accent-strong:${color};--sapid-color-primary:${color};}`;
            basic += `.casdog-auth-root button{background-color:${color}!important;}`;
        }
        const radius = Number(theme.borderRadius);
        if (Number.isInteger(radius) && radius >= 0 && radius <= 100) basic += `.casdog-auth-root :is(button,input,select,.stack){border-radius:${radius}px!important;}`;
        if (theme.themeType === 'dark') basic += '.casdog-auth-root{color-scheme:dark;--text:#f1f5f9;--surface:#172233;--line:#526070;color:var(--text);background-color:#172233;}';
        if (theme.isCompact === true) basic += '.casdog-auth-root .stack{gap:8px;}';
    }
    const background = safeUrl(data.formBackgroundUrl);
    const mobile = safeUrl(data.formBackgroundUrlMobile) || background;
    if (background) basic += `.casdog-auth-root{background-image:url(${JSON.stringify(background)});background-size:cover;}`;
    if (mobile) basic += `@media(max-width:640px){.casdog-auth-root{background-image:url(${JSON.stringify(mobile)});}}`;
    const offset = [1,2,3,4].includes(Number(data.formOffset)) ? Number(data.formOffset) : 2;
    basic += '.casdog-auth-root>.stack{width:100%;max-width:720px;margin-inline:auto;}';
    if (offset === 1) basic += '@media(min-width:641px){.casdog-auth-root>.stack{margin-inline-start:0;}}';
    if (offset === 3) basic += '@media(min-width:641px){.casdog-auth-root>.stack{margin-inline-end:0;}}';
    if (offset === 4) basic += '@media(min-width:641px){.casdog-auth-root{display:grid;grid-template-columns:minmax(0,1fr) minmax(0,1fr);gap:24px;align-items:start;}.casdog-auth-root>.stack{grid-column:2;grid-row:1;}.casdog-auth-root>.application-theme-side{grid-column:1;grid-row:1;}.casdog-auth-root>.application-theme-footer{grid-column:1/-1;}}@media(max-width:640px){.casdog-auth-root>.application-theme-side{display:none!important;}}';
    style(basic + scopedCss(data.formCss) + (data.formCssMobile ? `@media(max-width:640px){${scopedCss(data.formCssMobile)}}` : ''));
    fontImports(data.formCss);
    fontImports(data.formCssMobile);
    if (offset === 4) htmlFrame(root, 'Application side panel', data.formSideHtml, false);
    htmlFrame(root, 'Application footer', data.footerHtml, true);
}
