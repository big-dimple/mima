export interface PasswordOptions {
  length: number;
  upper: boolean;
  lower: boolean;
  digits: boolean;
  symbols: boolean;
}

export const DEFAULT_PASSWORD_OPTIONS: PasswordOptions = {
  length: 20,
  upper: true,
  lower: true,
  digits: true,
  symbols: true,
};

const SETS = {
  upper: 'ABCDEFGHJKLMNPQRSTUVWXYZ',
  lower: 'abcdefghijkmnpqrstuvwxyz',
  digits: '23456789',
  symbols: '!@#$%^&*()-_=+[]{};:,.?',
};

/** 使用 Web Crypto（Node 22 / 浏览器通用）生成无偏随机密码，保证每类字符至少出现一次。 */
export function generatePassword(opts: PasswordOptions = DEFAULT_PASSWORD_OPTIONS): string {
  const pools = (Object.keys(SETS) as (keyof typeof SETS)[]).filter((k) => opts[k]);
  if (pools.length === 0 || opts.length < pools.length || opts.length > 128) {
    throw new Error('invalid password options');
  }
  const alphabet = pools.map((k) => SETS[k]).join('');
  const chars: string[] = pools.map((k) => pick(SETS[k]));
  while (chars.length < opts.length) chars.push(pick(alphabet));
  // Fisher–Yates 洗牌，避免"每类首字符固定在前"的模式
  for (let i = chars.length - 1; i > 0; i--) {
    const j = randomInt(i + 1);
    const a = chars[i]!;
    chars[i] = chars[j]!;
    chars[j] = a;
  }
  return chars.join('');
}

function pick(set: string): string {
  return set[randomInt(set.length)]!;
}

/** 拒绝采样，消除模偏差。 */
function randomInt(maxExclusive: number): number {
  const limit = Math.floor(0xffffffff / maxExclusive) * maxExclusive;
  const buf = new Uint32Array(1);
  for (;;) {
    globalThis.crypto.getRandomValues(buf);
    if (buf[0]! < limit) return buf[0]! % maxExclusive;
  }
}
