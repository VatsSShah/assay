/**
 * Record the Assay demo as a real 1920x1080 video.
 *
 * This is a live capture, not an animation of a saved log: it spawns `bash demo/run_demo.sh`,
 * streams the process's actual stdout/stderr into a terminal page as it arrives, and grabs a
 * frame every 1/FPS seconds. Frames differ because the process is producing output while the
 * camera is rolling. Nothing is pre-baked and no jump cut is applied.
 *
 * Pipeline: headless Chromium (CDP Page.captureScreenshot, JPEG) -> ffmpeg image2pipe -> VP8/WebM.
 *
 * Usage: node demo/record.mjs <out.webm> [transcript.txt] [frames-dir]
 */
import { spawn } from 'node:child_process';
import { mkdirSync, writeFileSync, createWriteStream } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, '..');

const CHROME = process.env.ASSAY_CHROME
  || '/opt/pw-browsers/chromium_headless_shell-1194/chrome-linux/headless_shell';
const FFMPEG = process.env.ASSAY_FFMPEG || '/opt/pw-browsers/ffmpeg-1011/ffmpeg-linux';
const PORT = Number(process.env.ASSAY_CDP_PORT || 9422);
const FPS = Number(process.env.ASSAY_FPS || 10);
const WIDTH = 1920, HEIGHT = 1080;

const outVideo = resolve(process.argv[2] || `${HERE}/out/assay-demo.webm`);
const outTranscript = resolve(process.argv[3] || `${HERE}/out/transcript.txt`);
const framesDir = process.argv[4] ? resolve(process.argv[4]) : null;

mkdirSync(dirname(outVideo), { recursive: true });
if (framesDir) mkdirSync(framesDir, { recursive: true });

const sleep = ms => new Promise(r => setTimeout(r, ms));

async function connect() {
  const chrome = spawn(CHROME, [
    '--headless', '--disable-gpu', '--no-sandbox', '--hide-scrollbars',
    '--force-device-scale-factor=1', '--disable-dev-shm-usage',
    `--remote-debugging-port=${PORT}`, `--window-size=${WIDTH},${HEIGHT}`, 'about:blank',
  ], { stdio: 'ignore' });

  let list = null;
  for (let i = 0; i < 40 && !list; i++) {
    await sleep(250);
    try { list = await (await fetch(`http://127.0.0.1:${PORT}/json/list`)).json(); } catch { /* retry */ }
  }
  if (!list || !list.length) throw new Error('chromium did not expose a debugging target');

  const ws = new WebSocket(list[0].webSocketDebuggerUrl);
  await new Promise((ok, bad) => { ws.onopen = ok; ws.onerror = bad; });
  let id = 0;
  const pending = new Map();
  ws.onmessage = e => {
    const msg = JSON.parse(e.data);
    if (msg.id && pending.has(msg.id)) { pending.get(msg.id)(msg.result); pending.delete(msg.id); }
  };
  const send = (method, params = {}) => new Promise(ok => {
    const n = ++id;
    pending.set(n, ok);
    ws.send(JSON.stringify({ id: n, method, params }));
  });
  return { chrome, send };
}

const { chrome, send } = await connect();
await send('Page.enable');
await send('Runtime.enable');
await send('Emulation.setDeviceMetricsOverride',
  { width: WIDTH, height: HEIGHT, deviceScaleFactor: 1, mobile: false });
await send('Page.navigate', { url: `file://${HERE}/terminal.html` });
await sleep(1200);
await send('Runtime.evaluate', { expression: 'window.assayStart()' });

// Sample every SAMPLE_EVERY frames for the validator. Deliberately NOT a whole number of
// seconds: at 10fps a 1 s interval aliases against the 1 s cursor blink, so identical samples
// would be reported for a screen that is in fact moving.
const SAMPLE_EVERY = Number(process.env.ASSAY_SAMPLE_EVERY || 7);

// Two non-obvious flags:
//  * `-vcodec mjpeg` -- image2pipe cannot sniff the codec from a raw JPEG stream and fails
//    with "no decoder found for: none" without it.
//  * `-i pipe:0` rather than `-i -` -- ffmpeg 7 maps `-` to the `fd:` protocol, which this
//    minimal build does not enable; it gives "Protocol not found. Did you mean file:fd:?".
//    The `pipe` protocol IS enabled, so name it explicitly.
const ffmpeg = spawn(FFMPEG, [
  '-y', '-f', 'image2pipe', '-vcodec', 'mjpeg', '-framerate', String(FPS), '-i', 'pipe:0',
  '-c:v', 'libvpx', '-b:v', '4M', '-deadline', 'realtime', '-cpu-used', '5',
  '-pix_fmt', 'yuv420p', '-auto-alt-ref', '0', outVideo,
], { stdio: ['pipe', 'ignore', 'pipe'] });
let ffmpegLog = '';
let ffmpegDead = false;
ffmpeg.stderr.on('data', d => { ffmpegLog += d; });
ffmpeg.stdin.on('error', err => {
  // A dead encoder must abort the recording loudly; silently capturing into a closed pipe
  // would produce a "successful" run with no video.
  ffmpegDead = true;
  console.error(`ffmpeg stdin error: ${err.message}\n${ffmpegLog.trim().split('\n').slice(-6).join('\n')}`);
});
let ffmpegClosed = false;
ffmpeg.on('close', code => {
  ffmpegClosed = true;
  if (code !== 0) ffmpegDead = true;
});

const started = Date.now();
const transcript = [];
let frames = 0;
let capturing = true;

async function write(chunk) {
  transcript.push(chunk);
  const elapsed = (Date.now() - started) / 1000;
  await send('Runtime.evaluate', {
    expression: `window.assayWrite(${JSON.stringify(chunk)}, ${elapsed})`,
    awaitPromise: false,
  });
}

async function grab() {
  if (ffmpegDead) throw new Error('encoder died mid-recording; refusing to report success');
  const shot = await send('Page.captureScreenshot', { format: 'jpeg', quality: 82 });
  if (!shot || !shot.data) return;
  const buf = Buffer.from(shot.data, 'base64');
  if (!ffmpeg.stdin.write(buf)) {
    await new Promise(ok => ffmpeg.stdin.once('drain', ok));   // respect backpressure
  }
  if (framesDir && frames % SAMPLE_EVERY === 0) {
    writeFileSync(`${framesDir}/frame-${String(frames).padStart(5, '0')}.jpg`, buf);
  }
  frames++;
}

// The camera runs on its own clock, independent of the process's output, so a quiet
// stretch still produces frames and the timeline stays honest.
let tickerError = null;
const ticker = (async () => {
  while (capturing) {
    const at = Date.now();
    try {
      await grab();
    } catch (err) {
      tickerError = err;
      capturing = false;
      return;
    }
    const spent = Date.now() - at;
    await sleep(Math.max(0, 1000 / FPS - spent));
  }
})();

await write('$ bash demo/run_demo.sh\n');

const demo = spawn('bash', [`${HERE}/run_demo.sh`], {
  cwd: ROOT,
  env: { ...process.env, ASSAY_DEMO_PAUSE: process.env.ASSAY_DEMO_PAUSE || '1.1', TERM: 'xterm-256color' },
  stdio: ['ignore', 'pipe', 'pipe'],
});

const queue = [];
let draining = false;
async function drain() {
  if (draining) return;
  draining = true;
  while (queue.length) await write(queue.shift());
  draining = false;
}
const onData = d => { queue.push(d.toString('utf8')); drain(); };
demo.stdout.on('data', onData);
demo.stderr.on('data', onData);

const demoExit = await new Promise(ok => demo.on('close', ok));
while (queue.length || draining) await sleep(50);

await write(`\n\x1b[1;32m$ echo "demo exit status: ${demoExit}"\x1b[0m\ndemo exit status: ${demoExit}\n`);
await sleep(2500);                       // hold the final frame so a viewer can read it
capturing = false;
await ticker;

ffmpeg.stdin.end();
// If the encoder already exited, 'close' has fired and awaiting it would hang forever.
const ffExit = ffmpegClosed
  ? (ffmpeg.exitCode ?? 1)
  : await new Promise(ok => ffmpeg.on('close', ok));
chrome.kill();
writeFileSync(`${dirname(outVideo)}/ffmpeg.log`, ffmpegLog, 'utf8');

if (tickerError) {
  console.error(String(tickerError));
  process.exit(1);
}

writeFileSync(outTranscript, transcript.join(''), 'utf8');
const duration = frames / FPS;
console.log(JSON.stringify({
  video: outVideo,
  sample_every_frames: SAMPLE_EVERY,
  sample_interval_s: Number((SAMPLE_EVERY / FPS).toFixed(3)),
  transcript: outTranscript,
  frames,
  fps: FPS,
  duration_s: Number(duration.toFixed(2)),
  resolution: `${WIDTH}x${HEIGHT}`,
  demo_exit: demoExit,
  ffmpeg_exit: ffExit,
  ffmpeg_tail: ffmpegLog.trim().split('\n').slice(-3).join(' | '),
}, null, 2));
process.exit(demoExit === 0 && ffExit === 0 ? 0 : 1);
