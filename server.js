require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const fileupload = require('express-fileupload');
const apiRoutes = require('./src/routes');

const OPTIONS = {
  useNewUrlParser: true,
  useFindAndModify: false,
  useUnifiedTopology: true,
};

mongoose.connect(process.env.DATABASE, OPTIONS);
mongoose.Promise = global.Promise;
mongoose.connection.on('error', (error) => {
  console.log('Erro: ', error.message);
});

const server = express();
server.use(cors());
server.use(express.json());
server.use(express.urlencoded({ extended: true }));
server.use(fileupload());

server.use(express.static(`${__dirname}/public`));

server.use('/', apiRoutes);

server.listen(process.env.PORT, () => {
  console.log(`Servidor rodando no endereço: ${process.env.BASE}`);
});
