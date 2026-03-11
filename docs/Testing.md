# Testing

## GUI Testing Strategy for Tauri v2 (Hybrid: Vitest Component Tests + Playwright E2E)
- **Fast Component Tests (Current Step Completed)**: Configured `vitest` + `@testing-library` in `apps/desktop/vitest.config.ts`.
- Environment is forced to `jsdom`.
- Tauri-specific mock implementations injected via `apps/desktop/src/test/setup.ts` to simulate OS native window operations gracefully.

## Next Steps for Testing Infrastructure
1. Continue building upon `playwright.config.ts` enforcing dynamic headless ports for future full integration passes.
2. Ensure any new React component inherently declares `data-testid` mappings within `src/test/selectors.ts` to uphold Testability by Design.
3. Hook GitHub Actions/CI strictly to Vitest passing conditions prior to release.
