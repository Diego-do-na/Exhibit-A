import { execSync } from 'node:child_process';

export function runCommand(base: string, name: string): string {
  return execSync(`ls ${base}/${name}`, { encoding: 'utf8' });
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
