const express = require('express');
const router = express.Router();
const controller = require('../controllers/index');

// Define routes
router.get('/resources', controller.getResources);
router.post('/resources', controller.createResource);
router.put('/resources/:id', controller.updateResource);
router.delete('/resources/:id', controller.deleteResource);

// 登录路由
router.post('/login', controller.login);

module.exports = router;