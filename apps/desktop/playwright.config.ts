import { defineConfig, devices } from '@playwright/test';

if (!process.env.VITE_PORT) {
    process.env.VITE_PORT = String(Math.floor(Math.random() * 10000) + 10000);
}
const PORT = process.env.VITE_PORT;

export default defineConfig({
  testDir: './test/e2e',
  outputDir: '../../docs/assets/playwright/test-results',
  fullyParallel: true,
  retries: 0,
  workers: 1,
  reporter: [
    ['html', { outputFolder: '../../docs/assets/playwright/report' }]
  ],
  use: {
    baseURL: `http://localhost:${PORT}`,
    trace: 'on',
    video: 'on',
    screenshot: 'on',
    viewport: { width: 1400, height: 900 },
  },
  webServer: {
    command: `npm run dev -- --port ${PORT} --strictPort`,
    port: Number(PORT),
    reuseExistingServer: false,
    timeout: 30000,
  },
  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
    },
  ],
});
