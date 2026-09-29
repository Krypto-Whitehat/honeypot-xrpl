// index.ts — Vercel-AI-Gateway-Beispiel (Setup-Schritt 3 der Anleitung).
// Läuft mit: node --env-file=.env.local index.ts
// Der Key liegt ausschließlich in .env.local (gitignored) — nie committen.
import { generateText } from 'ai';
import { gateway } from '@ai-sdk/gateway';

// openai/gpt-5.5 erfordert Paid-Credits (Free-Tier: "no_providers_available");
// openai/gpt-5-mini ist free-tier-verifiziert (29.09.2026) und läuft sofort.
const MODEL = process.env.AI_GATEWAY_MODEL || 'openai/gpt-5-mini';

const { text } = await generateText({
  model: gateway(MODEL),
  prompt: 'Invent a new holiday and describe its traditions.',
});

console.log(text);
