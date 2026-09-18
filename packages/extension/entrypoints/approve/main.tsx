import React from 'react';
import ReactDOM from 'react-dom/client';

import '../popup/style.css';
import { ApproveApp } from './ApproveApp';

const root = document.getElementById('root');
if (!root) throw new Error('#root not found');

ReactDOM.createRoot(root).render(
  <React.StrictMode>
    <ApproveApp />
  </React.StrictMode>,
);
