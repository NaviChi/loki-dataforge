import { test, expect } from '@playwright/test';

// Tauri creates a webview. Testing the natively compiled app via Playwright can be done in Tauri v2
// by having the app emit a CDP port, but often the pure playwright way on generic OS is a web-runner.
// We will launch the Vite dynamic port 0 server.

test('Loki Data Forge E2E - Network DiskWizard & Virtual Healer', async ({ page }) => {
  // Assuming Playwright is pointing its baseURL to the Vite port 0 instance started by the webServer config
  await page.goto('/');

  // Verify core UI bounds
  await expect(page.getByTestId('readonly-badge')).toBeVisible();
  
  // Click Mesh Setup
  await page.getByRole('button', { name: /Mesh Setup/i }).click();

  // The QuicSwarm popup should appear
  await expect(page.getByText('QuicSwarm Mesh Peer')).toBeVisible();

  // Ensure QUIC inputs exist (ensuring UI bounds hold)
  const peerInput = page.getByPlaceholder('192.168.1.100:4433');
  await expect(peerInput).toBeVisible();
  await peerInput.fill('127.0.0.1:4433');

  const connectBtn = page.getByRole('button', { name: /Connect Peer/i });
  await expect(connectBtn).toBeEnabled();

  // Close wizard
  await page.getByRole('button', { name: /Cancel/i }).click();

  // Test Advanced options bounds for Healer module
  await page.getByText('Advanced').click();
  const healCheckbox = page.getByTestId('heal-ransomware-checkbox');
  await expect(healCheckbox).toBeVisible();
  await healCheckbox.check();

  // Confirming bounds
  await page.getByTestId('run-scan-btn').click();
  
  // It should error "Set a source drive/image path first" because we didn't add one
  await expect(page.getByTestId('status-message')).toContainText('Set a source drive');

  // Validate strict OS-native UI snapshot for Virtual Healer Advanced Panel
  // Playwright handles visual regressions ensuring our glassmorphism doesn't regress
  await expect(page).toHaveScreenshot('virtual-healer-advanced-panel.png', { maxDiffPixelRatio: 0.1, timeout: 5000 });
});
