const express = require('express');
const authRoutes = require('./routes/auth.routes');
const surveyRoutes = require('./routes/survey.routes');
const recommendationRoutes = require('./routes/recom.routes');
const db = require('./config/db');
const cors=require('cors');
// const { verifyToken } = require('./middlewares/Auth.middleware');

require('dotenv').config();
db();

const PORT = process.env.PORT || 9000;
const app = express();

app.use(cors())

app.use(express.json());

app.use('/api/auth', authRoutes);

// app.use(verifyToken);

app.use('/api/survey', surveyRoutes);
app.use('/api/destinations', recommendationRoutes);

app.listen(PORT, () => {
    console.log(`server is running http://localhost:${PORT}/api`)
});