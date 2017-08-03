/**
 * Created by sandeepkumar on 03/08/17.
 */
import express from 'express';
import config from 'config';
import MessageValidator from 'sns-validator';
import cors from 'cors';
import bodyParser from 'body-parser';
import morgan from 'morgan';
import helmet from 'helmet';
import swaggerUi from 'swagger-ui-express';
import swaggerJSDoc from 'swagger-jsdoc';

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

app.post('/validate', function (req, res) {
  validator.validate(req.body, function (err, message) {
    if (err) {
      // Your message could not be validated.
      res.statusCode(500).join({ message: 'Your message could not be validated.' });
      return;
    }
    console.log(message);
    res.statusCode(200).join({ message: 'Your message validated.' });
  });
})

app.listen(config.PORT, function () {
  console.log('App listening on port 3000!')
})