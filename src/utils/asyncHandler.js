/**
 * 包装异步路由/中间件：
 * - 捕获异常并返回统一的 JSON 500 响应
 * - 可选 logLabel 便于定位
 */
function asyncHandler(fn, { logLabel } = {}) {
  return (req, res, next) => Promise.resolve(fn(req, res, next)).catch(err => {
    try { console.error(logLabel ? `${logLabel}:` : '', err); } catch {}
    if (!res.headersSent) return res.status(500).json({ message: '服务器错误' });
  });
}

module.exports = { asyncHandler };
