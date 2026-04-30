import Link from "next/link";

export default function Home() {
  return (
    <main>
      <h1>Chio receipts template</h1>
      <p>
        This is the M07 P1 skeleton. The chat Route Handler lives at{" "}
        <code>/api/chat</code> and the receipts viewer at{" "}
        <Link href="/receipts">/receipts</Link>. P5 will replace the
        skeleton with a runnable chat experience and a local receipt sink.
      </p>
    </main>
  );
}
