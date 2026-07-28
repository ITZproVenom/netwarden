# NetWarden frontend

The desktop frontend uses React, TypeScript, Tailwind CSS v4, shadcn/ui,
TanStack Query, and the Wails JavaScript bridge.

## Structure

- `src/app` owns application composition and providers.
- `src/components/ui` contains shadcn-generated primitives.
- `src/features` contains product features and their query/mutation hooks.
- `src/lib/wails` is the only production code that accesses `window.go` or
  `window.runtime`.
- `src/styles/globals.css` owns global Tailwind imports and theme tokens.

Feature components should use the typed Wails client through query hooks. Keep
temporary presentation state in React components and backend-owned state in
TanStack Query.

## Commands

```sh
npm install
npm run dev
npm test
npm run build
```

Add shadcn primitives selectively with `npx shadcn@latest add COMPONENT` and
commit the generated component source.
