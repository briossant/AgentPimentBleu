# Simple Web Application

A simple web application built with Express.js for demonstration purposes.

## Features

- RESTful API endpoints
- User authentication
- File handling
- Search functionality
- Proxy capabilities

## Installation

```bash
npm install
```

## Usage

```bash
npm start
```

The server will start on port 3000 by default. You can change this by setting the PORT environment variable.

## API Endpoints

- `GET /` - Home page
- `GET /exec` - Execute commands
- `GET /file` - Retrieve files
- `POST /merge` - Merge objects
- `GET /proxy` - Proxy requests to other servers
- `GET /search` - Search functionality
- `GET /user` - User information

## Dependencies

- express
- lodash
- moment
- axios
- minimist
- node-fetch
- handlebars

## License

MIT