import { spawnSync } from 'node:child_process';
import path from 'node:path';

export function runCommand(base: string, name: string): string {
  return spawnSync('ls', [path.join(base, name)], { encoding: 'utf8' }).stdout || '';
}

export class App {
  base: string;

  constructor(base: string) {
    this.base = base;
  }

  handleRequest(name: string): string {
    return runCommand(this.base, name);
  }
}
