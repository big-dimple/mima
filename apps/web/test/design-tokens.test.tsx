import { readdirSync, readFileSync } from 'node:fs';
import { extname, join, resolve } from 'node:path';
import { describe, expect, it } from 'vitest';

const root = resolve(import.meta.dirname, '../../..');
const runtimeLayoutTokens = new Set(['--list-width', '--nav-width']);

describe('shared design tokens', () => {
  it('defines every CSS variable used by the Web app and extension', () => {
    const sources = [
      readFileSync(join(root, 'packages/ui-tokens/tokens.css'), 'utf8'),
      ...cssFiles(join(root, 'apps/web/src')).map((path) => readFileSync(path, 'utf8')),
      ...cssFiles(join(root, 'apps/extension/src')).map((path) => readFileSync(path, 'utf8')),
    ];
    const definitions = new Set(
      sources.flatMap((source) => [...source.matchAll(/(--[a-z0-9-]+)\s*:/gi)].map((match) => match[1]!)),
    );
    const usages = new Set(
      sources.flatMap((source) => [...source.matchAll(/var\((--[a-z0-9-]+)/gi)].map((match) => match[1]!)),
    );

    expect([...usages].filter((token) => !definitions.has(token) && !runtimeLayoutTokens.has(token)).sort()).toEqual([]);
  });

  it('keeps primary button text at readable contrast', () => {
    const tokens = readFileSync(join(root, 'packages/ui-tokens/tokens.css'), 'utf8');
    const foreground = tokenColor(tokens, '--accent-contrast');
    const background = tokenColor(tokens, '--accent');
    expect(contrastRatio(foreground, background)).toBeGreaterThanOrEqual(4.5);
  });
});

function cssFiles(directory: string): string[] {
  return readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) return cssFiles(path);
    return extname(entry.name) === '.css' ? [path] : [];
  });
}

function tokenColor(source: string, token: string): string {
  const escaped = token.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const match = source.match(new RegExp(`${escaped}\\s*:\\s*(#[0-9a-f]{6})`, 'i'));
  if (!match?.[1]) throw new Error(`Missing color token: ${token}`);
  return match[1];
}

function contrastRatio(first: string, second: string): number {
  const firstLuminance = luminance(first);
  const secondLuminance = luminance(second);
  const lighter = Math.max(firstLuminance, secondLuminance);
  const darker = Math.min(firstLuminance, secondLuminance);
  return (lighter + 0.05) / (darker + 0.05);
}

function luminance(color: string): number {
  const channels = color.slice(1).match(/.{2}/g);
  if (!channels || channels.length !== 3) throw new Error(`Unsupported color: ${color}`);
  const [red, green, blue] = channels.map((channel) => {
    const normalized = Number.parseInt(channel, 16) / 255;
    return normalized <= 0.04045
      ? normalized / 12.92
      : ((normalized + 0.055) / 1.055) ** 2.4;
  });
  return 0.2126 * red! + 0.7152 * green! + 0.0722 * blue!;
}
