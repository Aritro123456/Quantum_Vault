export type Timing = { mode: string; operation: string; payload_bytes: number | null; median_ms: number; p95_ms: number; min_ms: number; max_ms: number; repetitions: number };
export type Run = { created_at_utc: string; environment: { python: string; os: string; cryptography: string; cpu: string }; configuration: { repetitions: number; warmup: number; sizes: number[]; modes: string[]; scope: string }; timings: Timing[]; sizes: {mode:string; payload_bytes:number; public_key_bytes:number; encapsulation_bytes:number; envelope_bytes:number; signed_total_bytes:number}[] };
export type Overview = { modes: { id: string; suite: string }[]; max_plaintext_bytes: number; signature_algorithm: string; runs: {id:string;created_at_utc:string;cases:number;samples:number;repetitions:number}[]; latest: Run | null; local_only: boolean };
export async function getOverview(): Promise<Overview> {
  const response = await fetch('/api/overview', { cache:'no-store' });
  if (!response.ok) throw new Error('Django API is unavailable. Start the backend on port 8001.');
  return response.json();
}
export async function postForm(path: string, data: FormData): Promise<Response> {
  const session = await fetch('/api/session', { cache:'no-store' });
  if (!session.ok) throw new Error('Unable to connect to Django. Check that the backend is running.');
  const { csrfToken } = await session.json();
  const response = await fetch(path, { method:'POST', headers:{ 'X-CSRFToken': csrfToken }, body:data });
  if (!response.ok) {
    const error = await response.json().catch(() => ({error:'The operation could not be completed.'}));
    throw new Error(error.error || 'The operation could not be completed.');
  }
  return response;
}
export async function saveDownload(response: Response, fallback: string) {
  const blob = await response.blob();
  const name = response.headers.get('content-disposition')?.match(/filename="([^"]+)"/)?.[1] || fallback;
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url; anchor.download = name; document.body.appendChild(anchor); anchor.click(); anchor.remove();
  setTimeout(() => URL.revokeObjectURL(url), 60000);
  return name;
}
export const modeNames: Record<string,string> = { postquantum:'Post-quantum', classical:'Classical', hybrid:'Hybrid' };
export const modeColors: Record<string,string> = { postquantum:'#6763d9', classical:'#87b6a5', hybrid:'#edb465' };
export function bytes(n: number) { return n >= 1048576 ? `${(n/1048576).toFixed(1)} MiB` : n >= 1024 ? `${(n/1024).toFixed(n%1024===0?0:1)} KiB` : `${n} B`; }
