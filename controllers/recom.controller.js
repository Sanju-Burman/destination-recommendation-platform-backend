// const destinations = require("../data/destinations");

// const reccom= (req, res) => {
//     const { travelStyle, budget, interests, activities } = req.body;

//     const matches = destinations.filter(dest => {
//         const matchesStyle = dest.styles.includes(travelStyle);
//         const matchesBudget = dest.averageCost <= budget;
//         const matchesInterest = dest.tags.some(tag => interests.includes(tag));
//         const matchesActivity = dest.activities.some(act => activities.includes(act));

//         return matchesStyle && matchesBudget && (matchesInterest || matchesActivity);
//     });

//     res.json(matches);
// };

// module.exports = {reccom};
