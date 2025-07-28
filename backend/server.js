const express = require('express')
const path = require('path')
const cors = require('cors')
const app = express()
require('dotenv').config()
const connectDB = require('./config/connect')
const userrouter = require('./routers/router')
const port = process.env.port || 4000;

connectDB()
app.use(cors())
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ limit: '10mb', extended: true }))
// app.use(express.static(path.join(__dirname ,' frontend')))
app.use(express.static(path.join(__dirname, '../frontend')))
app.use(express.json())

app.use('/api', userrouter)

app.listen(port, ()=>{
    // console.log(`http://localhost:${port}`);
})
app.get('/', (req, res)=>{
    res.sendFile(path.join(__dirname, '../frontend/index.html'))
    
})
