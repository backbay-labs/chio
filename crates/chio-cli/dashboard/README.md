# Chio Receipt Dashboard

Operator-facing dashboard for browsing receipts, delegation lineage, and backend
aggregates from the trust-control service.

## Commands

```sh
npm run dev
npm run test
npm run build
```

## Runtime contract

- The dashboard reads a bearer token from `?token=` on first load, stores it in
  `sessionStorage`, and removes it from the visible URL.
- Receipt lists come from `/v1/receipts/query`.
- Agent cost history comes from `/v1/receipts/analytics` rather than
  reconstructing totals client-side from paged receipt subsets.
- Delegation inspection comes from `/v1/lineage/:capabilityId` and
  `/v1/lineage/:capabilityId/chain`.
- Relay alert cards read canonical alert and trend reports independently. A
  missing trend report renders `none` and must not hide a firing alert.
- The relay primary route is selected from the highest-severity firing alert,
  not from report array order.

## Production notes

- Build output is written to `dist/`.
- The Vite dev server proxies `/v1/*` to `http://localhost:8080`.
- Bundle splitting is configured so the table and UI stacks do not collapse
  into one large chunk, and the cost sparkline uses lightweight SVG rendering
  instead of shipping a charting framework.
