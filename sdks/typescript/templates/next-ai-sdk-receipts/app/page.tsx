import Link from "next/link";

export default function Home() {
  return (
    <main>
      <h1>Chio receipts template</h1>
      <p>
        This is the starter skeleton. The chat Route Handler lives at{" "}
        <code>/api/chat</code> and the receipts viewer at{" "}
        <Link href="/receipts">/receipts</Link>. Replace the skeleton with
        your own chat experience backed by a local receipt sink.
      </p>
    </main>
  );
}
