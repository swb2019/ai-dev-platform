module.exports = new Proxy(
  {},
  {
    get: (_target, prop) => (prop === '__esModule' ? false : prop),
  },
);
