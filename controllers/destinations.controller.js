const Destination = require('../models/destination.model');

const getDestination= async (req, res) => {
    try {
        const destinations = await Destination.find();
        res.json(destinations);
    } catch (error) {
        res.status(500).json({ message: 'Server Error on get Destinetion' });
    }
};

module.exports = {getDestination};
