import { useCallback, useEffect, useRef, useState } from 'react';

const LINE_HEIGHT = 18;
const OVERSCAN = 30;

type WorkerMessage =
  | { type: 'ready'; lineCount: number }
  | { type: 'range'; requestId: number; start: number; lines: string[] };

/** Renders only the visible log lines; parsing and slicing stay off the UI thread. */
export default function LogTextViewer({ content }: { content: string }) {
  const containerRef = useRef<HTMLDivElement>(null);
  const workerRef = useRef<Worker | null>(null);
  const requestIdRef = useRef(0);
  const frameRef = useRef<number | null>(null);
  const [lineCount, setLineCount] = useState(0);
  const [visible, setVisible] = useState<{ start: number; lines: string[] }>({ start: 0, lines: [] });
  const [ready, setReady] = useState(false);

  const requestVisibleRange = useCallback(() => {
    const worker = workerRef.current;
    const container = containerRef.current;
    if (!worker || !container || !ready) return;

    const first = Math.max(0, Math.floor(container.scrollTop / LINE_HEIGHT) - OVERSCAN);
    const count = Math.ceil(container.clientHeight / LINE_HEIGHT) + OVERSCAN * 2;
    const requestId = ++requestIdRef.current;
    worker.postMessage({ type: 'range', requestId, start: first, count });
  }, [ready]);

  useEffect(() => {
    const worker = new Worker(new URL('./logText.worker.ts', import.meta.url), { type: 'module' });
    workerRef.current = worker;
    setReady(false);
    setLineCount(0);
    setVisible({ start: 0, lines: [] });

    worker.onmessage = (event: MessageEvent<WorkerMessage>) => {
      const message = event.data;
      if (message.type === 'ready') {
        setLineCount(message.lineCount);
        setReady(true);
      } else if (message.requestId === requestIdRef.current) {
        setVisible({ start: message.start, lines: message.lines });
      }
    };
    worker.onerror = () => setReady(false);
    worker.postMessage({ type: 'init', content });

    return () => {
      worker.terminate();
      if (workerRef.current === worker) workerRef.current = null;
      if (frameRef.current !== null) cancelAnimationFrame(frameRef.current);
    };
  }, [content]);

  useEffect(() => {
    if (ready) requestVisibleRange();
  }, [ready, requestVisibleRange]);

  const onScroll = () => {
    if (frameRef.current !== null) cancelAnimationFrame(frameRef.current);
    frameRef.current = requestAnimationFrame(() => {
      frameRef.current = null;
      requestVisibleRange();
    });
  };

  return (
    <div
      ref={containerRef}
      onScroll={onScroll}
      aria-label="Contenido del log"
      style={{ width: '100%', height: '100%', minHeight: 0, flex: '1 1 auto', alignSelf: 'stretch', overflow: 'auto', fontFamily: 'Consolas, monospace', fontSize: 11, lineHeight: `${LINE_HEIGHT}px`, color: '#c4d0dc' }}
    >
      {!ready ? <div style={{ padding: 8, color: '#73869a' }}>Preparando visor del log…</div> : (
        <div style={{ minWidth: 'max-content' }}>
          <div aria-hidden="true" style={{ height: visible.start * LINE_HEIGHT }} />
          {visible.lines.map((line, index) => (
            <div key={visible.start + index} style={{ height: LINE_HEIGHT, whiteSpace: 'pre', paddingRight: 12 }}>{line || ' '}</div>
          ))}
          <div aria-hidden="true" style={{ height: Math.max(0, lineCount - visible.start - visible.lines.length) * LINE_HEIGHT }} />
        </div>
      )}
    </div>
  );
}
