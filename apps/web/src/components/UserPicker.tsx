import { useEffect, useRef, useState } from 'react';
import { AlertCircle, Loader2, Search, X } from 'lucide-react';
import type { UserSearchResult } from '@mima/contracts';
import { useApp } from '../state/app-context.ts';
import { IconButton } from './IconButton.tsx';
import styles from './UserPicker.module.css';

interface UserPickerProps {
  value: string;
  onChange: (userId: string, user?: UserSearchResult) => void;
  excludeIds?: string[];
  placeholder?: string;
  disabled?: boolean;
  label: string;
  inlineOptions?: boolean;
}

export function UserPicker({
  value,
  onChange,
  excludeIds = [],
  placeholder = '搜索姓名或域账号',
  disabled = false,
  label,
  inlineOptions = false,
}: UserPickerProps) {
  const { api } = useApp();
  const [query, setQuery] = useState('');
  const [results, setResults] = useState<UserSearchResult[]>([]);
  const [selected, setSelected] = useState<UserSearchResult | null>(null);
  const [open, setOpen] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(false);
  const [activeIndex, setActiveIndex] = useState(0);
  const [retryNonce, setRetryNonce] = useState(0);
  const requestSequence = useRef(0);
  const hydrationSequence = useRef(0);
  const rootRef = useRef<HTMLDivElement>(null);
  const excludedIdsKey = excludeIds.join('\u0000');

  useEffect(() => {
    const sequence = ++hydrationSequence.current;
    if (!value) {
      setSelected(null);
      if (!open) setQuery('');
      return;
    }
    if (selected?.id === value) {
      if (!open) setQuery(userLabel(selected));
      return;
    }
    void api
      .searchUsers('', [value], 1)
      .then((response) => {
        if (sequence !== hydrationSequence.current) return;
        const current = response.users.find((user) => user.id === value) ?? null;
        setSelected(current);
        if (current && !open) setQuery(userLabel(current));
      })
      .catch(() => undefined);
  }, [api, open, selected, value]);

  useEffect(() => {
    const sequence = ++requestSequence.current;
    if (!open) {
      setLoading(false);
      return;
    }
    const timer = window.setTimeout(() => {
      setLoading(true);
      setError(false);
      const excludedIds = new Set(excludedIdsKey.split('\u0000').filter(Boolean));
      void api
        .searchUsers(query, value ? [value] : [])
        .then((response) => {
          if (sequence !== requestSequence.current) return;
          const filtered = response.users.filter(
            (user) => !excludedIds.has(user.id) || user.id === value,
          );
          setResults(filtered);
          const current = filtered.find((user) => user.id === value) ?? null;
          setSelected(current);
          setActiveIndex(0);
        })
        .catch(() => {
          if (sequence === requestSequence.current) setError(true);
        })
        .finally(() => {
          if (sequence === requestSequence.current) setLoading(false);
        });
    }, open ? 300 : 0);
    return () => window.clearTimeout(timer);
  }, [api, excludedIdsKey, open, query, retryNonce, value]);

  const choose = (user: UserSearchResult) => {
    setSelected(user);
    setQuery(userLabel(user));
    setOpen(false);
    onChange(user.id, user);
  };

  const visible = results.filter((user) => user.id !== value || open);

  return (
    <div
      className={styles.root}
      ref={rootRef}
      onBlur={(event) => {
        if (!rootRef.current?.contains(event.relatedTarget as Node | null)) setOpen(false);
      }}
    >
      <div className={styles.inputWrap}>
        <Search size={15} aria-hidden />
        <input
          className={styles.input}
          aria-label={label}
          role="combobox"
          aria-expanded={open}
          aria-controls={`${label.replace(/\s+/g, '-')}-options`}
          aria-autocomplete="list"
          value={query}
          disabled={disabled}
          placeholder={placeholder}
          onFocus={(event) => {
            setOpen(true);
            event.currentTarget.select();
          }}
          onChange={(event) => {
            setQuery(event.target.value);
            setOpen(true);
            setResults([]);
            setLoading(true);
            if (value) {
              setSelected(null);
              onChange('');
            }
          }}
          onKeyDown={(event) => {
            if (event.key === 'ArrowDown') {
              event.preventDefault();
              setOpen(true);
              setActiveIndex((index) => Math.min(index + 1, Math.max(visible.length - 1, 0)));
            } else if (event.key === 'ArrowUp') {
              event.preventDefault();
              setActiveIndex((index) => Math.max(index - 1, 0));
            } else if (event.key === 'Enter' && open && visible[activeIndex]) {
              event.preventDefault();
              choose(visible[activeIndex]);
            } else if (event.key === 'Escape') {
              setOpen(false);
              if (selected) setQuery(userLabel(selected));
            }
          }}
        />
        {loading && <Loader2 size={15} className={styles.spin} aria-label="正在搜索" />}
        {value && !loading && (
          <IconButton
            label="清除已选用户"
            onClick={() => {
              setSelected(null);
              setQuery('');
              onChange('');
            }}
          >
            <X size={14} />
          </IconButton>
        )}
      </div>
      {open && (
        <div
          className={[styles.options, inlineOptions ? styles.inlineOptions : ''].join(' ')}
          id={`${label.replace(/\s+/g, '-')}-options`}
          role="listbox"
        >
          {error ? (
            <button className={styles.state} type="button" onClick={() => setRetryNonce((value) => value + 1)}>
              <AlertCircle size={15} aria-hidden /> 搜索失败，点击重试
            </button>
          ) : !loading && visible.length === 0 ? (
            <div className={styles.state}>没有匹配的用户</div>
          ) : (
            visible.map((user, index) => (
              <button
                type="button"
                role="option"
                aria-selected={index === activeIndex}
                className={[styles.option, index === activeIndex ? styles.active : ''].join(' ')}
                key={user.id}
                onMouseDown={(event) => event.preventDefault()}
                onMouseEnter={() => setActiveIndex(index)}
                onClick={() => choose(user)}
              >
                <span>{user.displayName}</span>
                <small>{user.username}</small>
              </button>
            ))
          )}
        </div>
      )}
    </div>
  );
}

export function UserMultiPicker({
  users,
  onChange,
  label,
}: {
  users: UserSearchResult[];
  onChange: (users: UserSearchResult[]) => void;
  label: string;
}) {
  return (
    <div className={styles.multi}>
      {users.length > 0 && (
        <div className={styles.chips}>
          {users.map((user) => (
            <span className={styles.chip} key={user.id}>
              <span>{user.displayName}</span>
              <button
                type="button"
                aria-label={`移除 ${user.displayName}`}
                onClick={() => onChange(users.filter((item) => item.id !== user.id))}
              >
                <X size={13} />
              </button>
            </span>
          ))}
        </div>
      )}
      <UserPicker
        value=""
        label={label}
        excludeIds={users.map((user) => user.id)}
        onChange={(_userId, user) => {
          if (user) onChange([...users, user]);
        }}
      />
    </div>
  );
}

function userLabel(user: UserSearchResult): string {
  return `${user.displayName} (${user.username})`;
}
