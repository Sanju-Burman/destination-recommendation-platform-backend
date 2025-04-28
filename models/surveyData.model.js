const mongoose = require("mongoose");

const SurveySchema = new mongoose.Schema({
    user: { type: mongoose.Schema.Types.ObjectId, ref:"Users"},
    travelStyle: { type: String, required: true },
    budget: { type: Number, required: true },
    interests: { type: [String], default: [] },
    activities: { type: [String], default: [] },
    createdAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model("Survey", SurveySchema);
