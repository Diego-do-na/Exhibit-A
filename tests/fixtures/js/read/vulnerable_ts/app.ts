import fs from 'node:fs';
import path from 'node:path';

export function readFile(filePath: string): string {
  return fs.readFileSync(filePath, 'utf8');
}

export class App {
  baseDir: string;
  routes: Record<string, (query: Record<string, string>) => { status: number; body: string }>;

  constructor(baseDir: string) {
    this.baseDir = baseDir;
    this.routes = {};
  }

  route(routePath: string, view: (query: Record<string, string>) => { status: number; body: string }) {
    this.routes[routePath] = view;
    return view;
  }

  handleRequest(method: string, routePath: string, query?: Record<string, string>) {
    const view = this.routes[routePath];
    if (method !== 'GET' || view == null) {
      return { status: 404, body: 'not found' };
    }
    return view(query || {});
  }
}

export function createApp(baseDir: string): App {
  const app = new App(baseDir);
  app.route('/download', function download(query) {
    const name = (query && query.name) || '';
    return { status: 200, body: readFile(path.join(app.baseDir, name)) };
  });
  return app;
}
