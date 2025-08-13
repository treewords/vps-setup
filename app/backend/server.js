const express = require('express');
const Docker = require('dockerode');
const http = require('http');
const { WebSocketServer } = require('ws');

const app = express();
const server = http.createServer(app);
const wss = new WebSocketServer({ server });

const port = 3001;
const docker = new Docker({ socketPath: '/var/run/docker.sock' });

app.use(express.json());

// --- REST API Endpoints ---

// Health check endpoint
app.get('/api/health', (req, res) => {
  res.status(200).json({ status: 'ok' });
});

// List all containers
app.get('/api/containers', async (req, res) => {
  try {
    const containers = await docker.listContainers({ all: true });
    res.json(containers);
  } catch (error) {
    console.error('Error fetching containers:', error);
    res.status(500).json({ message: 'Error fetching containers', error: error.message });
  }
});

// Inspect a container
app.get('/api/containers/:id', async (req, res) => {
  try {
    const container = docker.getContainer(req.params.id);
    const data = await container.inspect();
    res.json(data);
  } catch (error) {
    console.error(`Error inspecting container ${req.params.id}:`, error);
    if (error.statusCode === 404) {
      res.status(404).json({ message: `Container ${req.params.id} not found.` });
    } else {
      res.status(500).json({ message: 'Error inspecting container', error: error.message });
    }
  }
});

// Get container logs (last 100 lines)
app.get('/api/containers/:id/logs', async (req, res) => {
    try {
        const container = docker.getContainer(req.params.id);
        const logStream = await container.logs({
            stdout: true,
            stderr: true,
            tail: 100, // Get last 100 lines
        });
        res.setHeader('Content-Type', 'text/plain');
        res.end(logStream);
    } catch (error) {
        console.error(`Error fetching logs for container ${req.params.id}:`, error);
        if (error.statusCode === 404) {
            res.status(404).json({ message: `Container ${req.params.id} not found.` });
        } else {
            res.status(500).json({ message: 'Error fetching logs', error: error.message });
        }
    }
});


// Start a container
app.post('/api/containers/:id/start', async (req, res) => {
  try {
    const container = docker.getContainer(req.params.id);
    await container.start();
    res.status(200).json({ message: `Container ${req.params.id} started successfully.` });
  } catch (error) {
    console.error(`Error starting container ${req.params.id}:`, error);
    if (error.statusCode === 404) {
      res.status(404).json({ message: `Container ${req.params.id} not found.` });
    } else if (error.statusCode === 304) {
      res.status(304).json({ message: `Container ${req.params.id} is already started.` });
    } else {
      res.status(500).json({ message: 'Error starting container', error: error.message });
    }
  }
});

// Stop a container
app.post('/api/containers/:id/stop', async (req, res) => {
  try {
    const container = docker.getContainer(req.params.id);
    await container.stop();
    res.status(200).json({ message: `Container ${req.params.id} stopped successfully.` });
  } catch (error) {
    console.error(`Error stopping container ${req.params.id}:`, error);
    if (error.statusCode === 404) {
      res.status(404).json({ message: `Container ${req.params.id} not found.` });
    } else if (error.statusCode === 304) {
      res.status(304).json({ message: `Container ${req.params.id} is already stopped.` });
    } else {
      res.status(500).json({ message: 'Error stopping container', error: error.message });
    }
  }
});

// Restart a container
app.post('/api/containers/:id/restart', async (req, res) => {
  try {
    const container = docker.getContainer(req.params.id);
    await container.restart();
    res.status(200).json({ message: `Container ${req.params.id} restarted successfully.` });
  } catch (error) {
    console.error(`Error restarting container ${req.params.id}:`, error);
    if (error.statusCode === 404) {
      res.status(404).json({ message: `Container ${req.params.id} not found.` });
    } else {
      res.status(500).json({ message: 'Error restarting container', error: error.message });
    }
  }
});

// --- WebSocket Server for Log Streaming ---

wss.on('connection', (ws) => {
  console.log('Client connected for log streaming');
  let logStream = null;

  ws.on('message', async (message) => {
    try {
      const { containerId } = JSON.parse(message);
      console.log(`Requesting logs for container: ${containerId}`);

      const container = docker.getContainer(containerId);
      if (!container) {
        ws.send(JSON.stringify({ error: 'Container not found' }));
        return;
      }

      // Start streaming logs
      logStream = await container.logs({
        follow: true,
        stdout: true,
        stderr: true,
        timestamps: true,
      });

      logStream.on('data', (chunk) => {
        // The chunk is a buffer, convert it to a string
        ws.send(JSON.stringify({ log: chunk.toString('utf8') }));
      });

      logStream.on('end', () => {
        ws.send(JSON.stringify({ log: 'Log stream ended.' }));
        ws.close();
      });

    } catch (error) {
      console.error('Error in WebSocket message handler:', error);
      ws.send(JSON.stringify({ error: 'Failed to start log stream', details: error.message }));
    }
  });

  ws.on('close', () => {
    console.log('Client disconnected');
    if (logStream) {
      // This is important to prevent resource leaks on the server
      logStream.destroy();
      console.log('Log stream terminated.');
    }
  });

  ws.on('error', (error) => {
    console.error('WebSocket error:', error);
    if (logStream) {
        logStream.destroy();
    }
  });
});

server.listen(port, () => {
  console.log(`Docker Manager backend listening at http://localhost:${port}`);
});
