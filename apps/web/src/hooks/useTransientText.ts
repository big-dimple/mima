import { useCallback, useEffect, useLayoutEffect, useRef } from 'react';

export function useTransientText(identity: string, active: boolean) {
  const elementRef = useRef<HTMLElement | null>(null);

  const bind = useCallback((element: HTMLElement | null) => {
    elementRef.current = element;
  }, []);

  const clear = useCallback(() => {
    elementRef.current?.replaceChildren();
  }, []);

  const show = useCallback((value: string) => {
    if (!elementRef.current) return false;
    elementRef.current.textContent = value;
    return true;
  }, []);

  useLayoutEffect(() => {
    clear();
  }, [clear, identity]);

  useEffect(() => {
    if (!active) clear();
  }, [active, clear]);

  useEffect(() => () => clear(), [clear]);

  return { bind, clear, show };
}
