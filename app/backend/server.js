const express = require('express');
const Docker = require('dockerode');
const http = require('http');
const { WebSocketServer } = require('ws');

const app = express();
const server = http.createServer(app);

// --- WebSocket Servers ---
const wss = new WebSocketServer({ noServer: true });
const terminalWss = new WebSocketServer({ noServer: true });

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

// Pause a container
app.post('/api/containers/:id/pause', async (req, res) => {
    try {
        const container = docker.getContainer(req.params.id);
        await container.pause();
        res.status(200).json({ message: `Container ${req.params.id} paused successfully.` });
    } catch (error) {
        console.error(`Error pausing container ${req.params.id}:`, error);
        if (error.statusCode === 404) {
            res.status(404).json({ message: `Container ${req.params.id} not found.` });
        } else {
            res.status(500).json({ message: 'Error pausing container', error: error.message });
        }
    }
});

// Unpause a container
app.post('/api/containers/:id/unpause', async (req, res) => {
    try {
        const container = docker.getContainer(req.params.id);
        await container.unpause();
        res.status(200).json({ message: `Container ${req.params.id} unpaused successfully.` });
    } catch (error) {
        console.error(`Error unpausing container ${req.params.id}:`, error);
        if (error.statusCode === 404) {
            res.status(404).json({ message: `Container ${req.params.id} not found.` });
        } else {
            res.status(500).json({ message: 'Error unpausing container', error: error.message });
        }
    }
});

// Remove a container
app.delete('/api/containers/:id', async (req, res) => {
    try {
        const container = docker.getContainer(req.params.id);
        await container.remove({ force: req.query.force === 'true' });
        res.status(200).json({ message: `Container ${req.params.id} removed successfully.` });
    } catch (error) {
        console.error(`Error removing container ${req.params.id}:`, error);
        if (error.statusCode === 404) {
            res.status(404).json({ message: `Container ${req.params.id} not found.` });
        } else if (error.statusCode === 409) {
            res.status(409).json({ message: 'You cannot remove a running container. Stop the container before attempting to remove it, or use the force option.' });
        } else {
            res.status(500).json({ message: 'Error removing container', error: error.message });
        }
    }
});

// --- WebSocket Server for Log and Stats Streaming ---

wss.on('connection', (ws) => {
  console.log('Client connected');
  let logStream = null;
  let statsStreams = [];

  const cleanup = () => {
    console.log('Cleaning up resources for disconnected client.');
    if (logStream) {
      logStream.destroy();
      logStream = null;
      console.log('Log stream terminated.');
    }
    if (statsStreams.length > 0) {
      statsStreams.forEach(s => s.destroy());
      statsStreams = [];
      console.log('All stats streams terminated.');
    }
  };

  ws.on('message', async (message) => {
    try {
      const data = JSON.parse(message);

      // Handle log streaming requests
      if (data.type === 'log' && data.containerId) {
        console.log(`Requesting logs for container: ${data.containerId}`);
        const container = docker.getContainer(data.containerId);
        if (!container) {
          ws.send(JSON.stringify({ type: 'log_error', error: 'Container not found' }));
          return;
        }

        logStream = await container.logs({
          follow: true, stdout: true, stderr: true, timestamps: true,
        });

        logStream.on('data', (chunk) => ws.send(JSON.stringify({ type: 'log_data', log: chunk.toString('utf8') })));
        logStream.on('end', () => ws.send(JSON.stringify({ type: 'log_end' })));
      }

      // Handle stats streaming requests
      if (data.type === 'stats') {
        console.log('Requesting stats for all running containers.');
        const containers = await docker.listContainers({ filters: { status: ['running'] } });

        // Stop any previous stats streams
        statsStreams.forEach(s => s.destroy());
        statsStreams = [];

        containers.forEach(containerInfo => {
          const container = docker.getContainer(containerInfo.Id);
          container.stats({ stream: true }, (err, stream) => {
            if (err) {
              console.error(`Error getting stats for ${containerInfo.Id}:`, err);
              return;
            }
            statsStreams.push(stream);
            stream.on('data', (chunk) => {
              const stats = JSON.parse(chunk.toString('utf8'));
              ws.send(JSON.stringify({ type: 'stats_data', id: containerInfo.Id, stats }));
            });
            stream.on('end', () => console.log(`Stats stream ended for ${containerInfo.Id}`));
          });
        });
      }

    } catch (error) {
      console.error('Error in WebSocket message handler:', error);
      ws.send(JSON.stringify({ type: 'error', error: 'Failed to process request', details: error.message }));
    }
  });

  ws.on('close', cleanup);

  ws.on('error', (error) => {
    console.error('WebSocket error:', error);
    if (logStream) {
        logStream.destroy();
    }
  });
});

terminalWss.on('connection', async (ws, req) => {
    // The container ID is expected to be in the URL, e.g., /ws/terminal/containerId
    const containerId = req.url.split('/').pop();
    console.log(`Requesting terminal for container: ${containerId}`);

    try {
        const container = docker.getContainer(containerId);
        const exec = await container.exec({
            Cmd: ['/bin/sh', '-c', 'TERM=xterm-256color; export TERM; /bin/sh'],
            AttachStdin: true,
            AttachStdout: true,
            AttachStderr: true,
            Tty: true,
        });

        const stream = await exec.start({ hijack: true, stdin: true });

        // Pipe WebSocket to container stdin
        ws.on('message', (data) => {
            stream.write(data);
        });

        // Pipe container stdout/stderr to WebSocket
        stream.on('data', (chunk) => {
            ws.send(chunk);
        });

        // Handle close events
        ws.on('close', () => {
            stream.end();
        });
        stream.on('end', () => {
            ws.close();
        });

    } catch (error) {
        console.error(`Error setting up terminal for ${containerId}:`, error);
        ws.send(`Error: ${error.message}`);
        ws.close();
    }
});


server.on('upgrade', (request, socket, head) => {
  const pathname = request.url.split('?')[0];

  if (pathname.startsWith('/ws/terminal/')) {
    terminalWss.handleUpgrade(request, socket, head, (ws) => {
      terminalWss.emit('connection', ws, request);
    });
  } else if (pathname === '/ws') {
    wss.handleUpgrade(request, socket, head, (ws) => {
      wss.emit('connection', ws, request);
    });
  } else {
    socket.destroy();
  }
});


server.listen(port, () => {
  console.log(`Docker Manager backend listening at http://localhost:${port}`);
});
