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
  const { query = {}, sort, limit } = options || {};
  let q = Model.find(query).lean();
  if (sort) q = q.sort(sort);
  if (Number.isFinite(limit) && limit > 0) q = q.limit(limit);
  let docs = await q.exec();
  try {
    docs = await attachAggregatePinyin(docs);
  } catch (_) { /* ignore pinyin failures */ }
  return docs;
}

module.exports = { listWithPinyin };
