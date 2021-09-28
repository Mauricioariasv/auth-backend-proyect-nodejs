const express = require('express');
const cors = require('cors');
const { dbConnection } = require('./db/config');
const path = require('path')
require('dotenv').config();

// Crear el servidor/aplicación de express
const app = express();

// Base de datos
dbConnection();


// Directorio Público
app.use( express.static('public') );

// CORS
app.use( cors() );

// Lectura y parseo del body
app.use( express.json() );


// Rutas
app.use( '/api/auth', require('./routes/auth') );

// ruta
app.get('*', (req, res) => {
    res.sendFile( path.resolve( __dirname, 'public/index.html'))
})

app.listen( process.env.PORT, () => {
    console.log(`Servidor corriendo en puerto ${ process.env.PORT }`);
});

