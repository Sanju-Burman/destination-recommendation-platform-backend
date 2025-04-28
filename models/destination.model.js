const mongoose = require('mongoose');

const DestinationSchema = new mongoose.Schema({
    name: {
        type: String,
        required: true,
        trim: true
    },
    imageUrl: {
        type: String,
        required: true,
        trim: true
    },
    averageCost: {
        type: Number,
        required: true,
        min: 0
    },
    styles: {
        type: [String], 
        required: true,
        validate: [arrayLimit, '{PATH} must have at least one style']
    },
    tags: {
        type: [String], 
        required: true,
        validate: [arrayLimit, '{PATH} must have at least one tag']
    },
    activities: {
        type: [String], 
        required: true,
        validate: [arrayLimit, '{PATH} must have at least one activity']
    },
    location: {
        type: String,
        required: true,
        trim: true
    },
    latitude: {
        type: Number,
        required: true,
        min: -90,
        max: 90
    },
    longitude: {
        type: Number,
        required: true,
        min: -180,
        max: 180
    }
}, { timestamps: true });

// Custom validation function for arrays
function arrayLimit(val) {
    return val.length > 0;
}

const Destination = mongoose.model('destinations', DestinationSchema);

module.exports = Destination;