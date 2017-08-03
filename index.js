/**
 * Created by sandeepkumar on 03/08/17.
 */
const express = require('express');
const bodyParser = require('body-parser');
const config = require('config');
const MessageValidator = require('sns-validator');

const validator = new MessageValidator();
const app = express();

app.use(bodyParser.urlencoded({ extended: false }))
app.use(bodyParser.json())

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