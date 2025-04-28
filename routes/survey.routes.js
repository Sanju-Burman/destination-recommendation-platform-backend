const express = require("express");
const router = express.Router();
const { submitSurvey, getSurvey } = require("../controllers/survey.controller");

router.post("/", submitSurvey);
router.get("/", getSurvey);

module.exports = router;
