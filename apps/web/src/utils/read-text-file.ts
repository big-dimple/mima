export async function readTextFile(file: File, maxBytes = 1024 * 1024) {
  if (file.size > maxBytes) throw new Error('文件过大，请确认选择了正确的 JSON 文件');
  if (typeof file.text === 'function') return file.text();
  return new Promise<string>((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(typeof reader.result === 'string' ? reader.result : '');
    reader.onerror = () => reject(new Error('文件读取失败，请重新选择'));
    reader.readAsText(file);
  });
}
