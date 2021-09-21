const express = require('express');

const verifyToken = require('../middlewares/authMiddleware');
const postsController = require('../controllers/postsController');

const router = express.Router();

// @route GET api/posts
// @desc Get posts
// @access Private
router.get('/', verifyToken, postsController.getPosts);

// @route POST api/posts
// @desc Create new post
// @access Private
router.post('/', verifyToken, postsController.createPost);

// @route PUT api/posts/:id
// @desc Update post
// @access Private
router.put('/:id', verifyToken, postsController.updatePost);

// @route DELETE api/posts/:id
// @desc Delete post
// @access Private
router.delete('/:id', verifyToken, postsController.deletePost);

// @route PATCH api/posts/:id
// @desc Like post
// @access Private
router.patch('/:id', postsController.likePost);

module.exports = router;
