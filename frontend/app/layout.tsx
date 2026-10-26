import type { Metadata } from 'next';
import './globals.css';
export const metadata: Metadata = { title: 'QuantumVault | Cryptographic workspace', description: 'Post-quantum file protection, signatures, and measured cryptographic comparisons.' };
export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return <html lang="en"><body>{children}</body></html>;
}
