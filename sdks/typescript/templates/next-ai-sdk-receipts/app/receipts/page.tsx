import { getLocalReceiptSink } from "../../lib/local-sink.js";

export const dynamic = "force-dynamic";

export default function ReceiptsPage() {
  const sink = getLocalReceiptSink();
  const receipts = sink.list();
  return (
    <main>
      <h1>Chio receipts</h1>
      <p>
        Local receipt sink. No outbound calls; the TTFRH bench asserts a
        zero-network first run.
      </p>
      <ul>
        {receipts.map(receipt => (
          <li key={receipt.id}>
            <strong>{receipt.id}</strong>
            <span>{receipt.verdict}</span>
            <small>{receipt.source}</small>
          </li>
        ))}
      </ul>
    </main>
  );
}
