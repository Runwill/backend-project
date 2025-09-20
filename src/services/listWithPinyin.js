const { attachAggregatePinyin } = require('../utils/pinyin');

/**
 * 通用列表获取 + 拼音聚合
 * @param {import('mongoose').Model} Model - Mongoose 模型
 * @param {Object} [options]
 * @param {Object} [options.query] - 查询条件
 * @param {Object} [options.sort] - 排序，如 { createdAt: -1 }
 * @param {number} [options.limit] - 限制条数
 * @returns {Promise<Array>} - 带 py 字段的文档数组（lean 对象）
 */
async function listWithPinyin(Model, options = {}) {
  const { query = {}, sort, limit, pinyin } = options || {};
  let q = Model.find(query).lean();
  if (sort) q = q.sort(sort);
  if (Number.isFinite(limit) && limit > 0) q = q.limit(limit);
  let docs = await q.exec();
  try {
    // 轻负载默认：只聚合常见中文字段；允许通过 options.pinyin.keys 覆盖
    const defaultKeys = ['cn','name','title','replace','content','lore','legend'];
    const opts = { ...(pinyin || {}), keys: (pinyin && Array.isArray(pinyin.keys) && pinyin.keys.length ? pinyin.keys : defaultKeys) };
    docs = await attachAggregatePinyin(docs, opts);
  } catch (_) { /* ignore pinyin failures */ }
  return docs;
}

module.exports = { listWithPinyin };
