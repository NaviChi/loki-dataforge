import { render, screen, fireEvent } from '@testing-library/react';
import { describe, it, expect, vi } from 'vitest';
import { App } from '../App';
import { Selectors } from './selectors';

// Mock matchMedia
Object.defineProperty(window, 'matchMedia', {
  writable: true,
  value: vi.fn().mockImplementation((query: string) => ({
    matches: false,
    media: query,
    onchange: null,
    addListener: vi.fn(), 
    removeListener: vi.fn(), 
    addEventListener: vi.fn(),
    removeEventListener: vi.fn(),
    dispatchEvent: vi.fn(),
  })),
});

describe('App GUI Testability (Vitest)', () => {
  it('renders read-only badge indicating default safe behavior', () => {
    render(<App />);
    const badge = screen.getByTestId(Selectors.readonlyBadge);
    expect(badge).toBeInTheDocument();
  });

  it('renders status message correctly', () => {
    render(<App />);
    const status = screen.getByTestId(Selectors.statusMessage);
    expect(status).toHaveTextContent(/Ready\. Read-only mode is enabled by default/i);
  });

  it('toggles theme when button is clicked', () => {
    render(<App />);
    const toggle = screen.getByTestId(Selectors.themeToggle);
    expect(toggle).toBeInTheDocument();
    
    // Initial theme should be dark (per state)
    expect(toggle).toHaveTextContent(/Light theme/i); // Button says 'Light theme' when in dark mode
    
    fireEvent.click(toggle);
    expect(toggle).toHaveTextContent(/Dark theme/i); // Switches to light mode
  });

  it('contains scan operation bounds', () => {
    render(<App />);
    const runScan = screen.getByTestId(Selectors.runScanBtn);
    expect(runScan).toBeInTheDocument();
    
    const recoverBtn = screen.getByTestId(Selectors.recoverBtn);
    expect(recoverBtn).toBeInTheDocument();
    expect(recoverBtn).toBeDisabled(); // Disabled initially without report/source
  });

  it('renders heal ransomware options ensuring data-testid availability', () => {
    render(<App />);
    const advancedTab = screen.getByText('Advanced');
    fireEvent.click(advancedTab);
    const healCheckbox = screen.getByTestId(Selectors.healRansomwareCheckbox);
    expect(healCheckbox).toBeInTheDocument();
    expect(healCheckbox).not.toBeChecked(); // defaults to false
  });
});
