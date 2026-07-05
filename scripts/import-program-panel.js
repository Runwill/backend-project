require('dotenv').config();

const fs = require('fs');
const path = require('path');
const mongoose = require('mongoose');
const serverConfig = require('../src/config/serverConfig');
const { ProgramPanel } = require('../src/models');

const DEFAULT_SOURCE = path.resolve(__dirname, '..', '..', 'card-html', 'base', 'program_panel.json');
const sourcePath = path.resolve(process.argv[2] || DEFAULT_SOURCE);

function readProgramPanel(filePath) {
  const data = JSON.parse(fs.readFileSync(filePath, 'utf8'));
  const panelId = data.panelId || data.view?.id;
  if (!data || panelId !== 'panel_term') throw new Error('program_panel.json 缺少 panel_term 标识');
  if (!Array.isArray(data.concepts)) throw new Error('program_panel.json 缺少 concepts 数组');
  if (data.tree) {
    if (!Array.isArray(data.tree.children)) throw new Error('program_panel.json 缺少 tree.children');
    return data;
  }
  if (!data.view?.main || !Array.isArray(data.view.main.children)) throw new Error('program_panel.json 缺少 view.main.children');
  if (!Array.isArray(data.sections) || !Array.isArray(data.statements)) {
    throw new Error('program_panel.json 缺少 sections/statements 数组');
  }
  return data;
}

function countTreeNodes(node) {
  if (!node) return 0;
  return 1 + (node.children || []).reduce((sum, child) => sum + countTreeNodes(child), 0);
}

async function main() {
  const data = readProgramPanel(sourcePath);
  await mongoose.connect(serverConfig.dbUrl);
  const panelId = data.panelId || data.view.id;
  const view = data.view || { type: 'panel', id: panelId };

  const doc = await ProgramPanel.findOneAndUpdate(
    { panelId },
    {
      $set: {
        version: data.version,
        source: data.source,
        renderer: data.renderer,
        concepts: data.concepts,
        sections: data.sections || [],
        statements: data.statements || [],
        tree: data.tree,
        view
      }
    },
    { upsert: true, new: true, setDefaultsOnInsert: true }
  ).lean();

  console.log(JSON.stringify({
    status: 'ok',
    db: serverConfig.dbUrl,
    source: sourcePath,
    panelId: doc.panelId,
    concepts: data.concepts.length,
    sections: (data.sections || []).length,
    statements: (data.statements || []).length,
    treeNodes: data.tree ? countTreeNodes(data.tree) : 0
  }, null, 2));
}

main()
  .catch(err => {
    console.error('[import-program-panel] failed:', err);
    process.exitCode = 1;
  })
  .finally(() => mongoose.disconnect());
