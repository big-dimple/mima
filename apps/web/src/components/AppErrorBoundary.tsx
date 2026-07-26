import { Component, type ErrorInfo, type ReactNode } from 'react';
import { ErrorState } from './AsyncState.tsx';

interface AppErrorBoundaryState {
  failed: boolean;
}

export class AppErrorBoundary extends Component<{ children: ReactNode }, AppErrorBoundaryState> {
  override state: AppErrorBoundaryState = { failed: false };

  static getDerivedStateFromError(): AppErrorBoundaryState {
    return { failed: true };
  }

  override componentDidCatch(error: Error, info: ErrorInfo): void {
    console.error('React render failed', error.name, info.componentStack);
  }

  override render(): ReactNode {
    if (this.state.failed) {
      return (
        <ErrorState
          variant="page"
          title="界面运行异常"
          message="当前页面未能安全完成渲染。请重新加载后再试。"
          onRetry={() => window.location.reload()}
        />
      );
    }
    return this.props.children;
  }
}
