import app, { createApp } from './app';

export { app, createApp };
export default app;

if (typeof module !== 'undefined' && module.exports) {
  module.exports = Object.assign(app, module.exports, {
    default: app,
    app,
    createApp,
  });
}
