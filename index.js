/**
 * Created by sandeepkumar on 03/08/17.
 */
import express from 'express';
import config from 'config';
import MessageValidator from './validator';
import cors from 'cors';
import bodyParser from 'body-parser';
import morgan from 'morgan';
import helmet from 'helmet';

const validator = new MessageValidator();
const app = express();
// Helmet helps you secure your Express apps by setting various HTTP headers
// https://github.com/helmetjs/helmet
app.use(helmet());

// Enable CORS with various options
// https://github.com/expressjs/cors
app.use(cors());

// Request logger
// https://github.com/expressjs/morgan
if (!config.test) {
  app.use(morgan('dev'));
}

// Parse incoming request bodies
// https://github.com/expressjs/body-parser
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

app.post('/validate', (req, res) => {
  validator.validate(req.body, (err, message) => {
    if (err) {
      // Your message could not be validated.
      res.status(500).json(err);
      return;
    }
    res.status(200).json(message);
  });
})

app.listen(config.PORT, () => {
  console.log('App listening on port 3000!')
})