// Deliberately vulnerable fixture for tests/smoke.sh (vuln-scan semgrep rules). Not real code.
const { app, BrowserWindow, ipcMain, shell } = require("electron");
const child_process = require("child_process");
function create() {
  const w = new BrowserWindow({ width: 800, webPreferences: { nodeIntegration: true, contextIsolation: false, webSecurity: false } });
  w.webContents.on("will-navigate", (e, url) => { e.preventDefault(); shell.openExternal(url); });
  shell.openExternal("https://example.com/help");   // constant: must NOT match
}
ipcMain.handle("run-tool", (event, cmd) => child_process.exec("tool " + cmd));
window.addEventListener("message", (ev) => { document.getElementById("o").innerHTML = ev.data.html; });
window.addEventListener("message", (ev) => { if (ev.origin !== "https://ok.example") return; go(ev.data); }); // must NOT match
app.on("certificate-error", (event, wc, url, err, cert, callback) => { event.preventDefault(); callback(true); });
const vm = require("vm");
function plugin(code) { return eval(code); }               // js-eval-dynamic
eval("1+1");                                               // constant: must NOT match
const view = { originWhitelist: ["*"], allowFileAccessFromFileURLs: true }; // rn-webview-wide-origin
