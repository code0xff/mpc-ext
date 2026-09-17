import React from 'react';
import ReactDOM from 'react-dom/client';

import { App } from './App';
import './style.css';

const root = document.getElementById('root');
if (!root) throw new Error('#root를 찾을 수 없습니다');

ReactDOM.createRoot(root).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);
