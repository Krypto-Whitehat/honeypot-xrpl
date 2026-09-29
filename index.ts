// index.ts — Vercel-AI-Gateway-Beispiel (Setup-Schritt 3 der Anleitung).
// Läuft mit: node --env-file=.env.local index.ts
// Der Key liegt ausschließlich in .env.local (gitignored) — nie committen.
import { generateText } from 'ai';
import { gateway } from '@ai-sdk/gateway';

const { text } = await generateText({
  model: gateway('openai/gpt-5.5'),
  prompt: 'Invent a new holiday and describe its traditions.',
});

console.log(text);
