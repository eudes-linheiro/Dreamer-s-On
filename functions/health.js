export function onRequestGet() {
  return Response.json({ status: 'ok' }, { headers: { 'Cache-Control': 'no-store' } });
}