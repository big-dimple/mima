import { readFile, writeFile } from 'node:fs/promises';
import { URL } from 'node:url';

const script = (await readFile(new URL('../dist/browser.global.js', import.meta.url), 'utf8'))
  .replaceAll('</script', '<\\/script');

const html = `<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'unsafe-inline' 'wasm-unsafe-eval'; style-src 'unsafe-inline'; img-src data:; connect-src 'none'; form-action 'none'; base-uri 'none'">
<title>Mima 企业恢复向导</title>
<style>
:root{color-scheme:light;font-family:Inter,"Microsoft YaHei",system-ui,sans-serif;color:#1f2933;background:#eef2f3}*{box-sizing:border-box}body{margin:0;min-height:100vh;background:#eef2f3}header{background:#fff;border-bottom:1px solid #dce3e5;padding:24px max(24px,calc((100vw - 980px)/2))}header h1{font-size:24px;margin:0 0 6px;letter-spacing:0}header p{margin:0;color:#5b6970;font-size:14px}.shell{max-width:980px;margin:0 auto;padding:28px 24px 52px}.boundary{display:flex;gap:12px;padding:16px 18px;background:#e7f4f1;border-left:4px solid #0f8a7b;color:#25433f;margin-bottom:24px}.boundary strong{display:block;margin-bottom:3px}.grid{display:grid;grid-template-columns:1fr 1fr;gap:18px}.panel{background:#fff;border:1px solid #d9e0e2;border-radius:6px;padding:22px}.panel h2{font-size:18px;margin:0 0 8px;letter-spacing:0}.panel>p{font-size:14px;color:#5b6970;line-height:1.7;margin:0 0 18px}.steps{margin:0 0 20px;padding-left:22px;color:#3f4d53;font-size:14px;line-height:1.8}button{min-height:42px;border:1px solid #0f766e;border-radius:5px;background:#0f766e;color:#fff;font:inherit;font-weight:650;padding:9px 15px;cursor:pointer;text-align:center}button:disabled{opacity:.55;cursor:wait}.file-download{display:block;width:100%;margin-top:9px;background:#fff;color:#0f766e}.file-row{display:block;margin:13px 0}.file-row span{display:block;font-size:13px;font-weight:700;margin-bottom:6px}.file-row input{display:block;width:100%;border:1px solid #cbd5d8;border-radius:5px;padding:10px;background:#fff;color:#34444a}.status{display:none;margin-top:16px;padding:13px 14px;border-radius:5px;font-size:14px;line-height:1.65}.status[data-state]{display:block}.status[data-state=working]{background:#eef4f7;color:#395866}.status[data-state=success]{background:#e8f6ef;color:#245c42}.status[data-state=error]{background:#fff0ed;color:#9d321f}.status strong,.status span{display:block}.foot{margin-top:22px;color:#64737a;font-size:13px;line-height:1.7}@media(max-width:760px){header{padding:20px}.shell{padding:20px}.grid{grid-template-columns:1fr}.panel{padding:18px}}
</style>
<style>
.file-row{margin:13px 0}.file-label{display:block;font-size:13px;font-weight:700;margin-bottom:6px}.file-picker{display:flex;align-items:center;gap:10px;min-height:44px;border:1px solid #cbd5d8;border-radius:5px;padding:6px;background:#fff}.file-row .file-input{position:absolute;display:block;width:1px;height:1px;padding:0;overflow:hidden;clip:rect(0 0 0 0);white-space:nowrap}.file-row .file-button{display:inline-block;flex:0 0 auto;margin:0;border:1px solid #9eabad;border-radius:4px;background:#f6f8f8;color:#24343a;font-size:13px;font-weight:650;padding:7px 11px;cursor:pointer}.file-row .file-name{display:block;min-width:0;margin:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:#5b6970;font-size:13px;font-weight:400}.file-input:focus-visible+.file-button{outline:2px solid #0f766e;outline-offset:2px}
</style>
</head>
<body>
<header><h1>Mima 企业恢复向导</h1><p>此文件可以在断网电脑上直接双击使用，无需安装任何软件。</p></header>
<main class="shell">
  <div class="boundary"><div><strong>全程离线</strong><span>向导不会连接网络，也不会保存到浏览器。完成后请关闭页面，并按公司要求妥善处理临时文件。</span></div></div>
  <div class="grid">
    <section class="panel">
      <h2>首次准备企业恢复</h2>
      <p>只需做一次。向导会自动生成一份公开清单和三份恢复材料，不需要填写名称、编号或保存路径。</p>
      <ol class="steps"><li>点击下面的按钮并选择一个空文件夹。</li><li>把三份恢复材料分别放到三个独立位置。</li><li>把公开清单带回平台，在“准备恢复”中登记。</li></ol>
      <button id="generate-kit" type="button">生成并保存恢复材料</button>
      <div id="generate-result" class="status" aria-live="polite"></div>
    </section>
    <section class="panel">
      <h2>处理一次恢复</h2>
      <p>管理员完成两人确认后，从平台下载一个处理包。这里选择处理包和任意两份不同的恢复材料即可。</p>
      <form id="recovery-form">
        <div class="file-row"><label class="file-label" for="case-package">1. 管理员下载的处理包</label><div class="file-picker"><input class="file-input" id="case-package" type="file" accept="application/json,.json" required><label class="file-button" for="case-package">选择文件</label><span class="file-name" id="case-package-name">尚未选择文件</span></div></div>
        <div class="file-row"><label class="file-label" for="share-one">2. 第一份恢复材料</label><div class="file-picker"><input class="file-input" id="share-one" type="file" accept=".mimashare,application/octet-stream,text/plain" required><label class="file-button" for="share-one">选择文件</label><span class="file-name" id="share-one-name">尚未选择文件</span></div></div>
        <div class="file-row"><label class="file-label" for="share-two">3. 第二份恢复材料</label><div class="file-picker"><input class="file-input" id="share-two" type="file" accept=".mimashare,application/octet-stream,text/plain" required><label class="file-button" for="share-two">选择文件</label><span class="file-name" id="share-two-name">尚未选择文件</span></div></div>
        <button id="recovery-submit" type="submit">核对并生成处理结果</button>
      </form>
      <div id="recovery-status" class="status" aria-live="polite"></div>
    </section>
  </div>
  <p class="foot">公开清单不含私密内容，可以登记到平台。任何一份恢复材料都不能单独恢复；实际处理必须使用三份中的任意两份。</p>
</main>
<script>${script}</script>
</body>
</html>`;

await writeFile(new URL('../dist/打开企业恢复向导.html', import.meta.url), html, 'utf8');
