import { beginChatGPTPlanSignIn } from '@/lib/server/chatgpt-plan';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

function callbackPort(request: Request): number {
  const host =
    request.headers.get('x-forwarded-host')?.split(',')[0]?.trim() ||
    request.headers.get('host') ||
    '';
  try {
    const url = new URL('http://' + host);
    if (url.port) return Number(url.port);
  } catch {
    // Fall through to the local default.
  }
  const configured = Number(process.env.OPENMAIC_PORT || 3000);
  return Number.isInteger(configured) && configured > 0 ? configured : 3000;
}

export async function POST(request: Request): Promise<Response> {
  try {
    const result = await beginChatGPTPlanSignIn(callbackPort(request));
    return Response.json(result);
  } catch (error) {
    const message = error instanceof Error ? error.message : 'ChatGPT sign-in is unavailable.';
    return Response.json({ error: message }, { status: 400 });
  }
}
