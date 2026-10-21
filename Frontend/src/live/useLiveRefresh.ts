import { useEffect, useRef } from "react";
import { useLive } from "./LiveContext";

// Coalesce notifications while a refresh is in flight. Pages still load normally
// on mount; later invalidations reuse their current filters and page offset.
export function useLiveRefresh(refresh: () => Promise<void>) {
  const { revision } = useLive();
  const latest = useRef(refresh);
  const seen = useRef(revision);
  const running = useRef(false);
  const pending = useRef(false);
  const mounted = useRef(false);
  useEffect(() => { latest.current = refresh; }, [refresh]);
  useEffect(() => {
    mounted.current = true;
    return () => { mounted.current = false; pending.current = false; };
  }, []);
  useEffect(() => {
    if (seen.current === revision) return;
    seen.current = revision;
    pending.current = true;
    if (running.current) return;
    async function drain() {
      running.current = true;
      try {
        while (mounted.current && pending.current) {
          pending.current = false;
          await latest.current();
        }
      } finally { running.current = false; }
    }
    void drain();
  }, [revision]);
}
