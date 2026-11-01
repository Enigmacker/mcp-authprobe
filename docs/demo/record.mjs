// Records docs/demo/demo.gif from real output: starts the lab, runs a scan,
// renders the terminal frames with the browser and assembles them with ffmpeg.
//
//   npm run build && node docs/demo/record.mjs
//
// Needs Google Chrome (or CHROME_PATH) and ffmpeg. Not part of the package.
import { spawn, execFileSync } from "node:child_process";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { chromium } from "playwright-core";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const cli = join(root, "dist/cli.js");
const out = join(root, "docs/demo/demo.gif");
const URL_ = "http://127.0.0.1:8787/mcp";

// --- 1. Real output -------------------------------------------------------
const work = mkdtempSync(join(tmpdir(), "map-demo-work-"));
const lab = spawn(process.execPath, [cli, "lab", "--port", "8787"], { stdio: ["ignore", "ignore", "pipe"] });
let banner = "";
lab.stderr.on("data", (d) => (banner += d));
await new Promise((r) => setTimeout(r, 1500));
const labLines = banner.split("\n").slice(0, 3).join("\n");

// login, with a scripted user who logs in as test / test and clicks Allow.
async function user(authorizationUrl) {
  const first = await fetch(authorizationUrl, { redirect: "manual" });
  const loginUrl = new URL(first.headers.get("location") ?? "", authorizationUrl);
  const logged = await fetch(loginUrl, { method: "POST", redirect: "manual", body: new URLSearchParams({ username: "test", password: "test" }) });
  const cookie = (logged.headers.get("set-cookie") ?? "").split(";")[0];
  const html = await (await fetch(authorizationUrl, { headers: { cookie } })).text();
  const form = new URLSearchParams();
  for (const m of html.matchAll(/<input type="hidden" name="([^"]+)" value="([^"]*)">/g)) form.set(m[1], m[2].replace(/&quot;/g, '"').replace(/&lt;/g, "<").replace(/&amp;/g, "&"));
  form.set("decision", "allow");
  const consent = await fetch(new URL("/consent", authorizationUrl), { method: "POST", redirect: "manual", headers: { cookie }, body: form });
  await fetch(consent.headers.get("location") ?? "", { redirect: "manual" });
}
const { runLoginCommand } = await import(join(root, "dist/login-command.js"));
let loginOut = "";
const write = process.stderr.write.bind(process.stderr);
process.stderr.write = (chunk) => ((loginOut += chunk), true);
await runLoginCommand({ mcpUrl: URL_, out: join(work, "lab-grant.json"), force: false, probe: true, browser: false, allowPrivate: true, secret: undefined, openUrl: user, timeoutMs: 10000 });
process.stderr.write = write;
const colour = { pass: "\x1b[32m", fail: "\x1b[1;31m", error: "\x1b[33m" };
const loginLines = loginOut
  .split("\n")
  .filter((l) => /^MAP-[A-Z]{3}\d{2}: (pass|fail|error|not_applicable|skipped) - /.test(l))
  .map((l) => {
    const [, id, status, msg] = /^(MAP-\S+): (\S+) - (.*)$/.exec(l);
    const label = status === "error" ? "inconclusive" : status === "fail" ? "FAIL" : status;
    const short = msg.length > 92 ? `${msg.slice(0, 90)}…` : msg;
    return `  ${colour[status] ?? "\x1b[2m"}${label.padEnd(12)}\x1b[0m ${id}  ${short}`;
  });
const written = /Test grant written to .*? \(mode 600\)/.exec(loginOut);
if (written) loginLines.push(written[0].replace(/written to .*? \(/, "written to lab-grant.json ("));

const env = { ...process.env, FORCE_COLOR: "1" };
let scan = "";
try {
  scan = execFileSync(process.execPath, [cli, "scan", URL_, "--allow-private", "--skip", "THR", "--credentials-file", "lab-grant.json"], { env, cwd: work }).toString();
} catch (e) {
  scan = e.stdout.toString(); // exit code 1: failing checks, as expected
}
lab.kill();
rmSync(work, { recursive: true, force: true });

// --- 2. Frames --------------------------------------------------------------
const PROMPT = "\x1b[1;32m$\x1b[0m ";
const frames = []; // { text, ms }
let screen = "";
const show = (ms) => frames.push({ text: screen, ms });
const type = (cmd) => {
  for (let i = 2; i <= cmd.length; i += 2) {
    frames.push({ text: `${screen}${PROMPT}${cmd.slice(0, i)}\x1b[7m \x1b[0m`, ms: 40 });
  }
  screen += `${PROMPT}${cmd}\n`;
  show(350);
};
const reveal = (lines, step = 3, ms = 110) => {
  for (let i = 0; i < lines.length; i += step) {
    screen += `${lines.slice(i, i + step).join("\n")}\n`;
    show(ms);
  }
};
type("npx mcp-authprobe lab &        # a deliberately vulnerable local server");
screen += `${labLines}\n\n`;
show(1500);
type(`npx mcp-authprobe login ${URL_} --allow-private --out lab-grant.json`);
screen += "\x1b[2m  (the browser opens: log in as test / test, click Allow)\x1b[0m\n";
show(1200);
reveal(loginLines, 1, 250);
show(2500);
screen = "";
type(`npx mcp-authprobe scan ${URL_} --allow-private --credentials-file lab-grant.json --skip THR`);
reveal(scan.replace(/\n+$/, "").split("\n"), 6, 130);
show(7000);

// --- 3. Render --------------------------------------------------------------
const esc = (s) => s.replace(/&/g, "&amp;").replace(/</g, "&lt;");
function ansiToHtml(text) {
  let html = "";
  let open = 0;
  for (const part of text.split(/(\x1b\[[0-9;]*m)/)) {
    const m = /^\x1b\[([0-9;]*)m$/.exec(part);
    if (!m) {
      html += esc(part);
      continue;
    }
    const codes = m[1].split(";").filter(Boolean).map(Number);
    if (codes.length === 0 || codes.includes(0)) {
      html += "</span>".repeat(open);
      open = 0;
      continue;
    }
    const cls = codes.map((c) => `c${c}`).join(" ");
    html += `<span class="${cls}">`;
    open += 1;
  }
  return html + "</span>".repeat(open);
}
const page = (text) => `<!doctype html><meta charset="utf-8"><style>
  body { margin: 0; background: #0d1117; }
  .win { margin: 0; padding: 0; height: 100vh; display: flex; flex-direction: column; }
  .bar { height: 30px; background: #161b22; display: flex; align-items: center; gap: 8px; padding-left: 14px; }
  .dot { width: 12px; height: 12px; border-radius: 50%; }
  /* Like a terminal: the newest lines stay at the bottom, older ones scroll away. */
  pre { flex: 1; overflow: hidden; margin: 0; padding: 14px 18px; color: #c9d1d9; font: 13px/1.45 "DejaVu Sans Mono", Menlo, Consolas, monospace; white-space: pre-wrap; word-break: break-word; }
  .c1 { font-weight: bold; } .c2 { color: #8b949e; } .c7 { background: #c9d1d9; }
  .c31 { color: #ff7b72; } .c32 { color: #3fb950; } .c33 { color: #d29922; }
</style><div class="win"><div class="bar"><span class="dot" style="background:#ff5f56"></span><span class="dot" style="background:#ffbd2e"></span><span class="dot" style="background:#27c93f"></span></div><pre><div>${ansiToHtml(text)}</div></pre></div>`;

const tmp = mkdtempSync(join(tmpdir(), "map-demo-"));
const browser = await chromium.launch(process.env.CHROME_PATH ? { executablePath: process.env.CHROME_PATH } : { channel: "chrome" });
const tab = await browser.newPage({ viewport: { width: 1180, height: 780 } });
const list = [];
for (const [i, f] of frames.entries()) {
  await tab.setContent(page(f.text));
  await tab.evaluate(() => {
    const pre = document.querySelector("pre");
    pre.scrollTop = pre.scrollHeight;
  });
  const file = join(tmp, `f${String(i).padStart(4, "0")}.png`);
  await tab.screenshot({ path: file });
  list.push(`file '${file}'\nduration ${(f.ms / 1000).toFixed(3)}`);
}
await browser.close();
// The concat demuxer needs the last file repeated.
list.push(`file '${join(tmp, `f${String(frames.length - 1).padStart(4, "0")}.png`)}'`);
writeFileSync(join(tmp, "list.txt"), list.join("\n"));
execFileSync("ffmpeg", [
  "-y", "-loglevel", "error", "-f", "concat", "-safe", "0", "-i", join(tmp, "list.txt"),
  "-vf", "scale=980:-1:flags=lanczos,split[a][b];[a]palettegen=max_colors=96:stats_mode=full[p];[b][p]paletteuse=dither=none",
  "-loop", "0", out,
]);
rmSync(tmp, { recursive: true, force: true });
console.log(`wrote ${out} (${frames.length} frames)`);
