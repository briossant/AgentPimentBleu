const express = require('express');
const { exec } = require('child_process');
const fs = require('fs');
const path = require('path');
const _ = require('lodash');
const axios = require('axios');
const Handlebars = require('handlebars');
const ejs = require('ejs');
const ms = require('ms');

const app = express();
const port = 3000;

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

let appConfig = { defaultRole: 'user', features: {} };
let comments = [];

app.get('/', (req, res) => {
    res.send('<h1>Vulnerable JavaScript App</h1><p>Explore the various endpoints to test vulnerabilities.</p> <p>Timestamp conversion using ms: ' + ms(100000) + '</p>');
});

app.get('/api/system/exec', (req, res) => {
    const cmd = req.query.cmd;
    if (!cmd) {
        return res.status(400).send('Missing "cmd" query parameter.');
    }
    exec(cmd, (error, stdout, stderr) => {
        if (error) {
            return res.status(500).send({ error: error.message, stderr });
        }
        res.send({ stdout, stderr });
    });
});

app.post('/api/config/merge', (req, res) => {
    try {
        _.merge(appConfig, req.body);
        res.send({ message: 'Config updated. New config:', currentConfig: appConfig, isAdmin: ({}).isAdmin || false });
    } catch (e) {
        res.status(500).send({error: 'Failed to merge config: ' + e.message });
    }
});

app.get('/api/fetch-url', async (req, res) => {
    const targetUrl = req.query.targetUrl;
    if (!targetUrl) {
        return res.status(400).send('Missing "targetUrl" query parameter.');
    }
    try {
        const response = await axios.get(targetUrl, { timeout: 3000 });
        res.send(response.data);
    } catch (error) {
        res.status(500).send('Error fetching URL: ' + (error.message || 'Unknown error'));
    }
});

app.get('/api/files/read', (req, res) => {
    const filename = req.query.filename;
    if (!filename) {
        return res.status(400).send('Missing "filename" query parameter.');
    }
    const filePath = path.join(__dirname, 'public_files', filename);
    fs.readFile(filePath, 'utf8', (err, data) => {
        if (err) {
            return res.status(404).send('File not found or access denied.');
        }
        res.type('text/plain').send(data);
    });
});

app.get('/search', (req, res) => {
    const query = req.query.query || '';
    res.render('search_results', { query: query });
});

app.get('/content', (req, res) => {
    const contentData = req.query.data || '<i>No data provided (try ?data=&lt;script&gt;alert(1)&lt;/script&gt;)</i>';
    const template = Handlebars.compile('<h1>Dynamic Content</h1><div>{{{content}}}</div>');
    const html = template({ content: contentData });
    res.send(html);
});


app.listen(port, () => {
    console.log(`Vulnerable JavaScript app listening at http://localhost:${port}`);
    const publicFilesDir = path.join(__dirname, 'public_files');
    if (!fs.existsSync(publicFilesDir)) fs.mkdirSync(publicFilesDir);
    fs.writeFileSync(path.join(publicFilesDir, 'welcome.txt'), 'Hello from a public file!');
});
