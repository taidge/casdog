pub const APP_CSS: &str = r#"
:root {
  color-scheme: light;
  --bg: #f3ede3;
  --bg-strong: #e5d4b3;
  --surface: rgba(255, 251, 244, 0.88);
  --surface-strong: #10253d;
  --surface-soft: rgba(16, 37, 61, 0.06);
  --line: rgba(16, 37, 61, 0.12);
  --text: #10253d;
  --text-soft: rgba(16, 37, 61, 0.68);
  --accent: #d06f3c;
  --accent-strong: #8f3b1f;
  --success: #237b56;
  --danger: #a63636;
  --shadow: 0 24px 60px rgba(17, 27, 44, 0.16);
}

* {
  box-sizing: border-box;
}

body {
  margin: 0;
  min-height: 100vh;
  background:
    radial-gradient(circle at top left, rgba(208, 111, 60, 0.15), transparent 32%),
    radial-gradient(circle at bottom right, rgba(16, 37, 61, 0.18), transparent 28%),
    linear-gradient(145deg, #f8f3ea, #efe3cd 46%, #d7c4a3);
  color: var(--text);
  font-family: "IBM Plex Sans", "Segoe UI", sans-serif;
}

.shell {
  display: grid;
  grid-template-columns: 320px minmax(0, 1fr);
  min-height: 100vh;
}

.sidebar {
  position: sticky;
  top: 0;
  height: 100vh;
  padding: 28px 24px;
  border-right: 1px solid var(--line);
  background: rgba(16, 37, 61, 0.92);
  color: #f5ead8;
  overflow: auto;
}

.brand {
  margin-bottom: 24px;
}

.eyebrow {
  margin: 0 0 8px;
  letter-spacing: 0.18em;
  text-transform: uppercase;
  font-size: 12px;
  color: rgba(245, 234, 216, 0.68);
}

.brand h1 {
  margin: 0;
  font-size: 38px;
  line-height: 0.92;
  font-family: "Iowan Old Style", "Palatino Linotype", Georgia, serif;
}

.brand p {
  margin: 12px 0 0;
  color: rgba(245, 234, 216, 0.78);
  line-height: 1.5;
}

.sidebar input,
.sidebar button,
.editor textarea,
.toolbar input {
  font: inherit;
}

.field {
  display: grid;
  gap: 8px;
  margin-bottom: 14px;
}

.field span,
.section-label {
  font-size: 12px;
  letter-spacing: 0.12em;
  text-transform: uppercase;
}

.text-input,
.editor textarea,
.login-card input {
  width: 100%;
  padding: 12px 14px;
  border: 1px solid var(--line);
  border-radius: 16px;
  background: rgba(255, 255, 255, 0.92);
  color: var(--text);
}

.sidebar .text-input {
  background: rgba(255, 255, 255, 0.08);
  border-color: rgba(255, 255, 255, 0.14);
  color: #fff;
}

.sidebar .text-input::placeholder {
  color: rgba(255, 255, 255, 0.42);
}

.nav-section {
  margin-top: 22px;
}

.nav-grid {
  display: grid;
  gap: 8px;
}

.nav-item,
.ghost-button,
.primary-button,
.danger-button,
.status-chip {
  border: 0;
  border-radius: 16px;
  transition: transform 160ms ease, background 160ms ease, box-shadow 160ms ease;
}

.nav-item {
  width: 100%;
  padding: 12px 14px;
  text-align: left;
  background: rgba(255, 255, 255, 0.04);
  color: inherit;
  cursor: pointer;
}

.nav-item:hover,
.ghost-button:hover,
.primary-button:hover,
.danger-button:hover {
  transform: translateY(-1px);
}

.nav-item.active {
  background: linear-gradient(135deg, rgba(208, 111, 60, 0.22), rgba(255, 255, 255, 0.12));
  box-shadow: inset 0 0 0 1px rgba(245, 234, 216, 0.14);
}

.main {
  padding: 30px;
}

.panel,
.dashboard-card,
.login-card,
.resource-layout > * {
  border: 1px solid var(--line);
  border-radius: 28px;
  background: var(--surface);
  box-shadow: var(--shadow);
  backdrop-filter: blur(18px);
}

.hero {
  display: grid;
  gap: 18px;
  margin-bottom: 26px;
  padding: 28px;
  animation: fade-up 320ms ease;
}

.hero h2 {
  margin: 0;
  font-size: 42px;
  line-height: 1;
  font-family: "Iowan Old Style", "Palatino Linotype", Georgia, serif;
}

.hero p {
  margin: 0;
  max-width: 760px;
  color: var(--text-soft);
  line-height: 1.6;
}

.badge-row,
.toolbar {
  display: flex;
  flex-wrap: wrap;
  gap: 10px;
  align-items: center;
}

.status-chip {
  padding: 9px 14px;
  background: var(--surface-soft);
  color: var(--text);
}

.status-chip.success {
  background: rgba(35, 123, 86, 0.12);
  color: var(--success);
}

.status-chip.warn {
  background: rgba(208, 111, 60, 0.12);
  color: var(--accent-strong);
}

.primary-button,
.ghost-button,
.danger-button {
  padding: 11px 16px;
  cursor: pointer;
}

.primary-button {
  background: linear-gradient(135deg, var(--accent), #f4b26b);
  color: #fff;
}

.ghost-button {
  background: rgba(16, 37, 61, 0.08);
  color: var(--text);
}

.danger-button {
  background: rgba(166, 54, 54, 0.1);
  color: var(--danger);
}

.dashboard-grid {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: 18px;
}

.dashboard-card {
  padding: 22px;
}

.dashboard-card h3,
.login-card h3,
.section-title {
  margin: 0 0 10px;
  font-size: 20px;
}

.dashboard-card p,
.login-card p {
  margin: 0;
  color: var(--text-soft);
  line-height: 1.5;
}

.resource-layout {
  display: grid;
  grid-template-columns: 360px minmax(0, 1fr);
  gap: 18px;
}

.list-pane,
.editor-pane,
.login-card {
  padding: 20px;
}

.list-scroll {
  display: grid;
  gap: 12px;
  max-height: calc(100vh - 260px);
  overflow: auto;
  padding-right: 4px;
}

.resource-card {
  padding: 16px;
  border: 1px solid transparent;
  border-radius: 18px;
  background: rgba(255, 255, 255, 0.82);
  cursor: pointer;
}

.resource-card.active {
  border-color: rgba(208, 111, 60, 0.4);
  box-shadow: inset 0 0 0 1px rgba(208, 111, 60, 0.18);
}

.resource-card h4 {
  margin: 0;
  font-size: 18px;
}

.resource-card p {
  margin: 8px 0 0;
  color: var(--text-soft);
}

.editor textarea {
  min-height: 520px;
  margin-top: 14px;
  padding: 18px;
  font-family: "IBM Plex Mono", Consolas, monospace;
  line-height: 1.55;
  resize: vertical;
}

.inline-message {
  margin-top: 14px;
  padding: 12px 14px;
  border-radius: 16px;
}

.inline-message.error {
  background: rgba(166, 54, 54, 0.1);
  color: var(--danger);
}

.inline-message.success {
  background: rgba(35, 123, 86, 0.12);
  color: var(--success);
}

.inline-message.neutral {
  background: rgba(16, 37, 61, 0.08);
  color: var(--text-soft);
}

@keyframes fade-up {
  from {
    opacity: 0;
    transform: translateY(8px);
  }
  to {
    opacity: 1;
    transform: translateY(0);
  }
}

@media (max-width: 1100px) {
  .shell {
    grid-template-columns: 1fr;
  }

  .sidebar {
    position: static;
    height: auto;
    border-right: 0;
    border-bottom: 1px solid rgba(255, 255, 255, 0.1);
  }

  .dashboard-grid,
  .resource-layout {
    grid-template-columns: 1fr;
  }

  .list-scroll {
    max-height: none;
  }
}
"#;
