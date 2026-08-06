import {
  canonicalJson,
  createEnterpriseRecoveryKit,
  inspectRecoveryShare,
} from '@mima/e2ee';
import { createRecoveryCaseTransfer } from './case-transfer.ts';
import { parseRecoveryCaseInput } from './protocol.ts';

type WritableFile = { write(value: string): Promise<void>; close(): Promise<void> };
type ChosenFile = { createWritable(): Promise<WritableFile> };
type ChosenDirectory = {
  getDirectoryHandle(name: string, options: { create: true }): Promise<ChosenDirectory>;
  getFileHandle(name: string, options: { create: true }): Promise<ChosenFile>;
};

const setupModeButton = element<HTMLButtonElement>('mode-setup');
const caseModeButton = element<HTMLButtonElement>('mode-case');
const setupPanel = element<HTMLElement>('setup-panel');
const casePanel = element<HTMLElement>('case-panel');
const generateButton = element<HTMLButtonElement>('generate-kit');
const generateResult = element<HTMLDivElement>('generate-result');
const recoveryForm = element<HTMLFormElement>('recovery-form');
const packageInput = element<HTMLInputElement>('case-package');
const firstShareInput = element<HTMLInputElement>('share-one');
const secondShareInput = element<HTMLInputElement>('share-two');
const recoveryStatus = element<HTMLDivElement>('recovery-status');
const recoverySubmit = element<HTMLButtonElement>('recovery-submit');

generateButton.addEventListener('click', () => void generateKit());
recoveryForm.addEventListener('submit', (event) => void processRecovery(event));
setupModeButton.addEventListener('click', () => setMode('setup'));
caseModeButton.addEventListener('click', () => setMode('case'));
bindFileName(packageInput, 'case-package-name');
bindFileName(firstShareInput, 'share-one-name');
bindFileName(secondShareInput, 'share-two-name');

function setMode(mode: 'setup' | 'case'): void {
  const setup = mode === 'setup';
  setupModeButton.setAttribute('aria-selected', String(setup));
  caseModeButton.setAttribute('aria-selected', String(!setup));
  setupPanel.hidden = !setup;
  casePanel.hidden = setup;
}

async function generateKit(): Promise<void> {
  generateButton.disabled = true;
  generateResult.dataset.state = 'working';
  generateResult.textContent = '正在生成恢复材料，请不要关闭本页…';
  try {
    const ceremonyId = `recovery-${new Date().toISOString().slice(0, 10)}-${crypto.randomUUID().slice(0, 8)}`;
    const kit = await createEnterpriseRecoveryKit(ceremonyId);
    const files = new Map<string, string>([
      ['企业恢复公开清单.json', `${canonicalJson({
        protocol: 'lm-e2ee-v1',
        kind: 'enterprise-recovery-manifest',
        ceremonyId: kit.ceremonyId,
        ceremonyDigest: kit.ceremonyDigest,
        publicEncryptionKey: kit.publicKey,
        keyFingerprint: kit.publicKeyFingerprint,
        threshold: kit.threshold,
        shareCount: kit.shareCount,
      })}\n`],
      ['恢复材料-1.mimashare', `${kit.shares[0]}\n`],
      ['恢复材料-2.mimashare', `${kit.shares[1]}\n`],
      ['恢复材料-3.mimashare', `${kit.shares[2]}\n`],
    ]);
    const picker = (window as Window & {
      showDirectoryPicker?: () => Promise<ChosenDirectory>;
    }).showDirectoryPicker;
    if (picker) {
      try {
        const root = await picker();
        const directory = await root.getDirectoryHandle(`企业恢复材料-${ceremonyId.slice(-8)}`, { create: true });
        for (const [name, value] of files) {
          const handle = await directory.getFileHandle(name, { create: true });
          const writable = await handle.createWritable();
          await writable.write(value);
          await writable.close();
        }
        generateResult.dataset.state = 'success';
        generateResult.innerHTML = '<strong>已经生成完成。</strong><span>请把三份“恢复材料”分别保存到三个独立位置；公开清单可以带回联网电脑登记。</span>';
        return;
      } catch (error) {
        if (!(error instanceof DOMException) || error.name !== 'AbortError') throw error;
      }
    }
    generateResult.dataset.state = 'success';
    generateResult.replaceChildren(message('没有选择保存文件夹，请依次下载下面四个文件。'));
    for (const [name, value] of files) {
      const button = document.createElement('button');
      button.type = 'button';
      button.className = 'file-download';
      button.textContent = `下载 ${name}`;
      button.addEventListener('click', () => downloadText(name, value));
      generateResult.append(button);
    }
  } catch (error) {
    generateResult.dataset.state = 'error';
    generateResult.textContent = friendlyError(error, '恢复材料生成失败，请关闭后重新打开向导');
  } finally {
    generateButton.disabled = false;
  }
}

async function processRecovery(event: Event): Promise<void> {
  event.preventDefault();
  const packageFile = packageInput.files?.[0];
  const firstShare = firstShareInput.files?.[0];
  const secondShare = secondShareInput.files?.[0];
  if (!packageFile || !firstShare || !secondShare) {
    setRecoveryStatus('error', '请选择平台恢复案件中下载的 JSON 文件，以及两份不同的恢复材料。');
    return;
  }
  recoverySubmit.disabled = true;
  setRecoveryStatus('working', '正在离线核对并处理，请不要关闭本页…');
  try {
    const [packageText, firstText, secondText] = await Promise.all([
      packageFile.text(),
      firstShare.text(),
      secondShare.text(),
    ]);
    const [firstInfo, secondInfo] = await Promise.all([
      inspectRecoveryShare(firstText.trim()),
      inspectRecoveryShare(secondText.trim()),
    ]);
    if (firstInfo.shareIndex === secondInfo.shareIndex) throw new Error('两份恢复材料相同，请重新选择');
    const input = parseRecoveryCaseInput(packageText);
    const transfer = await createRecoveryCaseTransfer(input, [firstText.trim(), secondText.trim()]);
    const fileName = `企业恢复处理结果-${input.caseId.slice(0, 8)}.json`;
    const value = `${canonicalJson(transfer as never)}\n`;
    setRecoveryStatus('success', '处理完成。请把下载的结果文件带回联网电脑，并在这次恢复案件中上传。');
    downloadText(fileName, value);
    const fallback = document.createElement('button');
    fallback.type = 'button';
    fallback.className = 'file-download';
    fallback.textContent = '再次下载处理结果';
    fallback.addEventListener('click', () => downloadText(fileName, value));
    recoveryStatus.append(fallback);
  } catch (error) {
    setRecoveryStatus('error', friendlyError(error, '处理失败，请确认处理包和两份材料属于同一套企业恢复设置'));
  } finally {
    recoverySubmit.disabled = false;
  }
}

function setRecoveryStatus(state: 'working' | 'success' | 'error', value: string): void {
  recoveryStatus.dataset.state = state;
  recoveryStatus.textContent = value;
}

function downloadText(fileName: string, value: string): void {
  const blob = new Blob([value], { type: 'application/octet-stream' });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = fileName;
  anchor.click();
  setTimeout(() => URL.revokeObjectURL(url), 0);
}

function message(value: string): HTMLSpanElement {
  const span = document.createElement('span');
  span.textContent = value;
  return span;
}

function bindFileName(input: HTMLInputElement, labelId: string): void {
  const label = element<HTMLSpanElement>(labelId);
  input.addEventListener('change', () => {
    label.textContent = input.files?.[0]?.name ?? '尚未选择文件';
  });
}

function friendlyError(error: unknown, fallback: string): string {
  if (!(error instanceof Error)) return fallback;
  if (/distinct|different|重复|相同/i.test(error.message)) return '两份恢复材料必须不同，请重新选择。';
  if (/belong together|ceremony|match|不匹配|不属于/i.test(error.message)) {
    return '处理包和恢复材料不属于同一套企业恢复设置，请重新选择。';
  }
  return error.message || fallback;
}

function element<T extends HTMLElement>(id: string): T {
  const value = document.getElementById(id);
  if (!value) throw new Error(`missing element: ${id}`);
  return value as T;
}
