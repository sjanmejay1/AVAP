import type { Metadata } from "next";
import { Archivo, JetBrains_Mono } from "next/font/google";
import "./globals.css";
import { AppProviders } from "@/providers/app-providers";

// Archivo is variable on both weight and width; the width axis is what the
// wide page titles use (design_system.md §4).
const archivo = Archivo({
  variable: "--font-sans",
  subsets: ["latin"],
  display: "swap",
  axes: ["wdth"],
});

const jetbrainsMono = JetBrains_Mono({
  variable: "--font-mono",
  subsets: ["latin"],
  display: "swap",
});

export const metadata: Metadata = {
  title: {
    default: "AVAP",
    template: "%s | AVAP",
  },
  description:
    "Scan your own hosts and networks with Nmap, see what is exposed, and get a risk-scored PDF report.",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html
      lang="en"
      suppressHydrationWarning
      className={`${archivo.variable} ${jetbrainsMono.variable}`}
    >
      <body className="min-h-screen bg-background font-sans text-foreground antialiased">
        <AppProviders>{children}</AppProviders>
      </body>
    </html>
  );
}
