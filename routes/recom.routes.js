const express = require("express");
const router = express.Router();
// const { reccom } = require("../controllers/recom.controller");
const { getDestination } = require("../controllers/destinations.controller");

// router.post("/", reccom);
router.get("/", getDestination);
module.exports = router;