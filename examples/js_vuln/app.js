const express = require('express');
const path = require('path');
const fs = require('fs');
const _ = require('lodash');
const moment = require('moment');
const axios = require('axios');
const minimist = require('minimist');
const fetch = require('node-fetch');
const handlebars = require('handlebars');

const app = express();
const port = process.env.PORT || 3000;

// Parse JSON body
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Serve static files
app.use(express.static(path.join(__dirname, 'public')));

// Set up handlebars as the view engine
app.set('view engine', 'handlebars');

// Routes
app.get('/', (req, res) => {
  res.render('index', { title: 'Home Page' });
});

// Vulnerable endpoint - Command Injection
app.get('/exec', (req, res) => {
  const command = req.query.cmd;
  const { exec } = require('child_process');
  
  // Vulnerable: Direct use of user input in exec
  exec(command, (error, stdout, stderr) => {
    if (error) {
      return res.status(500).send(stderr);
    }
    res.send(stdout);
  });
});

// Vulnerable endpoint - Path Traversal
app.get('/file', (req, res) => {
  const fileName = req.query.name;
  
  // Vulnerable: No path validation
  const filePath = path.join(__dirname, 'files', fileName);
  
  fs.readFile(filePath, 'utf8', (err, data) => {
    if (err) {
      return res.status(404).send('File not found');
    }
    res.send(data);
  });
});

// Vulnerable endpoint - Prototype Pollution
app.post('/merge', (req, res) => {
  const userObj = req.body;
  const defaultObj = { role: 'user', permissions: [] };
  
  // Vulnerable: Using lodash.merge can lead to prototype pollution
  const result = _.merge({}, defaultObj, userObj);
  
  res.json(result);
});

// Vulnerable endpoint - SSRF
app.get('/proxy', async (req, res) => {
  const url = req.query.url;
  
  try {
    // Vulnerable: No URL validation
    const response = await axios.get(url);
    res.json(response.data);
  } catch (error) {
    res.status(500).send('Error fetching URL');
  }
});

// Vulnerable endpoint - XSS
app.get('/search', (req, res) => {
  const query = req.query.q;
  
  // Vulnerable: Directly inserting user input into HTML
  const html = `
    <html>
      <head><title>Search Results</title></head>
      <body>
        <h1>Search Results for: ${query}</h1>
        <div id="results"></div>
        <script>
          document.getElementById('results').innerHTML = 'You searched for: ${query}';
        </script>
      </body>
    </html>
  `;
  
  res.send(html);
});

// Vulnerable endpoint - NoSQL Injection
app.get('/user', (req, res) => {
  const username = req.query.username;
  
  // This is just a simulation since we don't have a real DB
  // But this pattern would be vulnerable to NoSQL injection
  const query = { username: username };
  
  // Simulating a database response
  res.json({ 
    message: `User query executed with: ${JSON.stringify(query)}`,
    user: { username, email: `${username}@example.com` }
  });
});

// Start the server
app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});

module.exports = app;