import type { Metadata } from "next";
import { Space_Grotesk, DM_Mono } from "next/font/google";
import "./globals.css";
import { Providers } from "./providers";

const grotesk = Space_Grotesk({ subsets: ["latin"], variable: "--font-loaded-grotesk" });
const dmMono = DM_Mono({
  subsets: ["latin"],
  weight: ["400", "500"],
  variable: "--font-loaded-mono",
  display: "swap",
});

export const metadata: Metadata = {
  title: "Prahari — email crypto posture, from the wire",
  description:
    "Prahari — SecureMailScope · AI-Assisted Cryptographic Security Posture Assessment. Passive analysis of SMTP, IMAP and POP3 traffic: every handshake parsed, every certificate checked, every weakness scored with its fix.",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className={`${grotesk.variable} ${dmMono.variable}`}>
      <body>
        <Providers>{children}</Providers>
      </body>
    </html>
  );
}
