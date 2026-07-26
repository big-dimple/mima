import React from 'react';
import { createRoot } from 'react-dom/client';
import * as Tooltip from '@radix-ui/react-tooltip';
import '@mima/ui-tokens/tokens.css';
import './global.css';
import { App } from './App.tsx';
import { AppErrorBoundary } from './components/AppErrorBoundary.tsx';
import { AppContext, createAppServices } from './state/app-context.ts';

const services = createAppServices();

createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <AppErrorBoundary>
      <AppContext.Provider value={services}>
        <Tooltip.Provider delayDuration={350}>
          <App />
        </Tooltip.Provider>
      </AppContext.Provider>
    </AppErrorBoundary>
  </React.StrictMode>,
);
