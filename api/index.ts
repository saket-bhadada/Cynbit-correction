import { createApp } from '../src/app';

const app = createApp();

export default app;

if (typeof module !== 'undefined' && module.exports) {
  module.exports = Object.assign(app, module.exports, {
    default: app,
    app,
  });
}
