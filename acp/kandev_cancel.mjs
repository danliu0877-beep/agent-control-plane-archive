// Node 22+ built-in WebSocket. No packages, shell, or policy changes.
const [endpoint, sessionId] = process.argv.slice(2);
const url = new URL(endpoint);
if (url.protocol !== 'ws:' || url.hostname !== '127.0.0.1' || url.pathname !== '/ws') {
  throw new Error('Loopback cancellation endpoint required');
}
const id = crypto.randomUUID();
const socket = new WebSocket(url);
const timer = setTimeout(() => { console.error('Cancellation timeout'); process.exit(2); }, 45000);
socket.addEventListener('open', () => socket.send(JSON.stringify({id, type: 'request', action: 'session.stop',
  payload: {session_id: sessionId, reason: 'ACP bounded cancellation', force: false}, timestamp: new Date().toISOString()})));
socket.addEventListener('message', ({data}) => {
  const response = JSON.parse(data);
  if (response.id !== id) return;
  clearTimeout(timer);
  if (response.type === 'error') { console.error(JSON.stringify(response)); process.exit(2); }
  console.log(JSON.stringify(response));
  socket.close();
});
socket.addEventListener('error', () => { clearTimeout(timer); console.error('WebSocket failed'); process.exit(2); });
