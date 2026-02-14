import express from "express";

const router = express.Router();

router.get('/', (req, res) => {
    res.send(`<p>Hello</p>`)
});

export default router;