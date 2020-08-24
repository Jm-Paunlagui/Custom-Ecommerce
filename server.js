if(process.env.NODE_ENV !== 'production'){
    require('dotenv').config({
        path: './config/config.env'
    })   
}

const express = require('express')
const bodyParser = require('body-parser')
const app = express()
const morgan = require('morgan')
const connectDB = require('./config/db')
const cors = require('cors')

connectDB()
app.use(bodyParser.json())

if(process.env.NODE_ENV === 'development'){
    app.use(cors({
        origin: process.env.CLIENT_URL
    }))

    app.use(morgan('dev'))
    console.log(process.env.CLIENT_URL)
}

app.use('/api/user/', require('./routes/auth.route'));

app.use((req, res) =>{
    res.status(404).json({
        success: false,
        message: 'Error code 404, page not found :(' 
    })
})

app.listen(process.env.PORT, () => {
    console.log(`App listening on port ${process.env.PORT}`);
    console.log(process.env.CLIENT_URL)
});