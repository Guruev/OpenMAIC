import { disconnectChatGPTPlan, getChatGPTPlanStatus } from '@/lib/server/chatgpt-plan';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

export async function GET(): Promise<Response> {
  return Response.json(await getChatGPTPlanStatus(), {
    headers: { 'cache-control': 'no-store' },
  });
}

export async function DELETE(): Promise<Response> {
  await disconnectChatGPTPlan();
  return Response.json({ connected: false });
}
