import type { Metadata } from 'next';
import { Inter } from 'next/font/google';

import '../styles/globals.css';

const inter = Inter({ subsets: ['latin'], variable: '--font-sans' });

export const metadata: Metadata = {
  title: 'AI Dev Platform',
  description: 'AI-powered development platform with security-first architecture',
  metadataBase: new URL('https://ai-dev-platform.local'),
  openGraph: {
    title: 'AI Dev Platform',
    description: 'AI-powered development platform with security-first architecture',
    type: 'website',
  },
  twitter: {
    card: 'summary_large_image',
    title: 'AI Dev Platform',
    description: 'AI-powered development platform with security-first architecture',
  },
  robots: {
    index: false,
    follow: false,
  },
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}): JSX.Element {
  return (
    <html lang="en" className={inter.variable}>
      <body className="min-h-screen bg-background font-sans antialiased">
        <main className="relative flex min-h-screen flex-col">
          {children}
        </main>
      </body>
    </html>
  );
}