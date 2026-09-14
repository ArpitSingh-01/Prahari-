export default function Loading() {
  return (
    <div className="mx-auto max-w-6xl space-y-6 py-8" aria-busy="true" aria-label="Loading">
      <div className="card h-24 animate-pulse" />
      <div className="grid gap-4 md:grid-cols-4">
        {[0, 1, 2, 3].map((i) => (
          <div key={i} className="card h-28 animate-pulse" />
        ))}
      </div>
      <div className="card h-64 animate-pulse" />
    </div>
  );
}
