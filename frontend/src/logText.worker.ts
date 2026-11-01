let lines: string[] = [];

self.onmessage = (event: MessageEvent<{ type: 'init'; content: string } | { type: 'range'; requestId: number; start: number; count: number }>) => {
  const message = event.data;
  if (message.type === 'init') {
    // Hillstone logs can use either CRLF or LF line endings.
    lines = message.content.split(/\r?\n/);
    self.postMessage({ type: 'ready', lineCount: lines.length });
    return;
  }

  const start = Math.max(0, Math.min(message.start, lines.length));
  const end = Math.min(lines.length, start + Math.max(0, message.count));
  self.postMessage({ type: 'range', requestId: message.requestId, start, lines: lines.slice(start, end) });
};

export {};
