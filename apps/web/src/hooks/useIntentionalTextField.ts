import { useCallback, useRef, useState } from 'react';
import type {
  ChangeEvent,
  ClipboardEvent,
  CompositionEvent,
  DragEvent,
  FocusEvent,
  KeyboardEvent,
} from 'react';

type TextControl = HTMLInputElement | HTMLTextAreaElement;

export function useIntentionalTextField(initialValue: string, onUserValue?: (value: string) => void) {
  const [value, setValueState] = useState(initialValue);
  const [touched, setTouched] = useState(false);
  const [activated, setActivated] = useState(false);
  const valueRef = useRef(initialValue);
  const acceptNextInputRef = useRef(false);
  const composingRef = useRef(false);
  const onUserValueRef = useRef(onUserValue);
  onUserValueRef.current = onUserValue;

  const armInput = useCallback((control: TextControl) => {
    acceptNextInputRef.current = true;
    setActivated(true);
    control.readOnly = false;
  }, []);

  const onKeyDown = useCallback((event: KeyboardEvent<TextControl>) => {
    const editsText = event.key.length === 1
      ? !event.ctrlKey && !event.metaKey && !event.altKey
      : event.key === 'Backspace'
        || event.key === 'Delete'
        || (event.key === 'Enter' && event.currentTarget instanceof HTMLTextAreaElement);
    if (editsText) armInput(event.currentTarget);
  }, [armInput]);

  const commitUserValue = useCallback((nextValue: string) => {
    valueRef.current = nextValue;
    acceptNextInputRef.current = false;
    setValueState(nextValue);
    setTouched(true);
    setActivated(true);
    onUserValueRef.current?.(nextValue);
  }, []);

  const replaceSelection = useCallback((control: TextControl, insertedValue: string) => {
    const currentValue = valueRef.current;
    const start = Math.min(control.selectionStart ?? currentValue.length, currentValue.length);
    const end = control.selectionEnd ?? start;
    commitUserValue(`${currentValue.slice(0, start)}${insertedValue}${currentValue.slice(Math.min(end, currentValue.length))}`);
  }, [commitUserValue]);

  const onPaste = useCallback((event: ClipboardEvent<TextControl>) => {
    event.preventDefault();
    replaceSelection(event.currentTarget, event.clipboardData.getData('text'));
  }, [replaceSelection]);

  const onCut = useCallback((event: ClipboardEvent<TextControl>) => {
    event.preventDefault();
    replaceSelection(event.currentTarget, '');
  }, [replaceSelection]);

  const onDrop = useCallback((event: DragEvent<TextControl>) => {
    event.preventDefault();
    replaceSelection(event.currentTarget, event.dataTransfer.getData('text'));
  }, [replaceSelection]);

  const onCompositionStart = useCallback((event: CompositionEvent<TextControl>) => {
    composingRef.current = true;
    acceptNextInputRef.current = true;
    setActivated(true);
    event.currentTarget.readOnly = false;
  }, []);

  const onCompositionEnd = useCallback(() => {
    composingRef.current = false;
    acceptNextInputRef.current = true;
  }, []);

  const onKeyUp = useCallback(() => {
    if (!composingRef.current) acceptNextInputRef.current = false;
  }, []);

  const onBlur = useCallback((_event: FocusEvent<TextControl>) => {
    acceptNextInputRef.current = false;
    composingRef.current = false;
  }, []);

  const onChange = useCallback((event: ChangeEvent<TextControl>) => {
    if (!composingRef.current && !acceptNextInputRef.current) {
      event.currentTarget.value = valueRef.current;
      return;
    }
    if (!composingRef.current) acceptNextInputRef.current = false;
    valueRef.current = event.currentTarget.value;
    setValueState(event.currentTarget.value);
    setTouched(true);
    onUserValueRef.current?.(event.currentTarget.value);
  }, []);

  const setFromUserAction = useCallback((nextValue: string) => {
    commitUserValue(nextValue);
  }, [commitUserValue]);

  const reset = useCallback((nextValue = '') => {
    valueRef.current = nextValue;
    acceptNextInputRef.current = false;
    composingRef.current = false;
    setValueState(nextValue);
    setTouched(false);
    setActivated(false);
  }, []);

  return {
    value,
    touched,
    activated,
    onChange,
    onKeyDown,
    onKeyUp,
    onBlur,
    onPaste,
    onCut,
    onDrop,
    onCompositionStart,
    onCompositionEnd,
    setFromUserAction,
    reset,
  };
}
