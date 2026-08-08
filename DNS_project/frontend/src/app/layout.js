import './globals.css';

export const metadata = {
  title: 'ReconX — Subdomain Intelligence Platform',
  description: 'Production-grade subdomain enumeration & takeover detection',
};

export default function RootLayout({ children }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
