const receipts = [
  {
    id: "local-template-receipt",
    verdict: "allow",
    source: "local receipt sink",
  },
];

export default function ReceiptsPage() {
  return (
    <main>
      <h1>Chio receipts</h1>
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
