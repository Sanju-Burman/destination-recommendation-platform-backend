const mongoose = require('mongoose');
const Survey = require('../models/surveyData.model')

const submitSurvey = async (req, res) => {
    try {
        if (!mongoose.Types.ObjectId.isValid(req.body.user)) {
            return res.status(400).json({ message: "Invalid user ID" });
        }
        const survey = new Survey(req.body);
        await survey.save();
        res.status(201).json({ message: "Survey submitted successfully" });
    } catch (error) {
        console.error("Survey submission failed:", error);
        res.status(500).json({ error: "Failed to submit survey" });
    }
};

const getSurvey= async (req, res) => {
    try {
        const surveys = await Survey.find().sort({ createdAt: -1 });
        res.json(surveys);
    } catch (error) {
        res.status(500).json({ error: "Failed to fetch survey data" });
    }
};


module.exports = { submitSurvey,getSurvey };