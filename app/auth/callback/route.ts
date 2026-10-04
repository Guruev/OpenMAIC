import { completeChatGPTPlanSignIn } from '@/lib/server/chatgpt-plan';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

function page(ok: boolean): Response {
  const title = ok ? 'ChatGPT connected' : 'ChatGPT sign-in failed';
  const message = ok
    ? 'OpenMAIC is now connected to your ChatGPT plan. You can close this window.'
    : 'OpenMAIC could not complete ChatGPT sign-in. Return to OpenMAIC and try again.';
  const html =
    '<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">' +
    '<title>' +
    title +
    '</title></head><body style="font-family:system-ui;padding:32px;max-width:680px;margin:auto">' +
    '<h1>' +
    title +
    '</h1><p>' +
    message +
    '</p>' +
    (ok ? '<script>setTimeout(function(){window.close()},700)</script>' : '') +
    '</body></html>';
  return new Response(html, {
    status: ok ? 200 : 400,
    headers: { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' },
  });
}

export async function GET(request: Request): Promise<Response> {
  try {
    await completeChatGPTPlanSignIn(new URL(request.url));
    return page(true);
  } catch {
    return page(false);
  }
}
