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
const si = require('systeminformation');
const docker = new Docker({ socketPath: '/var/run/docker.sock' });
const mongoose = require('mongoose');

const User = require('./models/User');

// Connect to MongoDB
mongoose.connect(process.env.MONGODB_URI)
    .then(() => {
        console.log('MongoDB connected...');
        // Seed initial admin user if no users exist
        const seedAdminUser = async () => {
            try {
                const userCount = await User.countDocuments();
                if (userCount === 0) {
                    console.log('No users found, creating default admin user...');
                    await User.create({
                        username: process.env.DEFAULT_ADMIN_USER,
                        password: process.env.DEFAULT_ADMIN_PASSWORD,
                        role: process.env.USER_ROLE,
                    });
                    console.log('Default admin user created with Admin role.');
                }
            } catch (error) {
                console.error('Error seeding admin user:', error);
            }
        };
        seedAdminUser();
    })
    .catch(err => console.error('MongoDB connection error:', err));


app.use(express.json());

// --- Routes ---
app.use('/api/auth', require('./routes/authRoutes'));
app.use('/api/containers', require('./routes/containerRoutes'));
app.use('/api/images', require('./routes/imageRoutes'));
app.use('/api/networks', require('./routes/networkRoutes'));
app.use('/api/volumes', require('./routes/volumeRoutes'));


const { protect, authorize } = require('./middleware/authMiddleware');

// --- REST API Endpoints ---

// Health check endpoint
app.get('/api/health', (req, res) => {
  res.status(200).json({ status: 'ok' });
});

// Get static system information
app.get('/api/system', protect, authorize('Admin', 'Developer', 'Viewer'), async (req, res) => {
    try {
        const [osInfo, cpu, dockerVersion, time] = await Promise.all([
            si.osInfo(),
            si.cpu(),
            docker.version(),
            si.time(),
        ]);
        res.json({
            os: `${osInfo.distro} ${osInfo.release}`,
            cpu: `${cpu.manufacturer} ${cpu.brand}`,
            dockerVersion: dockerVersion.Version,
            uptime: time.uptime,
        });
    } catch (error) {
        console.error('Error fetching system info:', error);
        res.status(500).json({ message: 'Error fetching system info', error: error.message });
    }
});

// --- WebSocket Server for Log and Stats Streaming ---

wss.on('connection', (ws) => {
  console.log('Client connected');
  let logStream = null;
  let statsStreams = [];
  let systemStatsInterval = null;

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
    if (systemStatsInterval) {
      clearInterval(systemStatsInterval);
      systemStatsInterval = null;
      console.log('System stats interval cleared.');
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

      // Handle system stats streaming requests
      if (data.type === 'get_system_stats') {
          console.log('Requesting system stats.');
          // Clear any existing interval
          if (systemStatsInterval) clearInterval(systemStatsInterval);

          systemStatsInterval = setInterval(async () => {
              try {
                  const [cpuLoad, mem, fs] = await Promise.all([
                      si.currentLoad(),
                      si.mem(),
                      si.fsSize(),
                  ]);
                  ws.send(JSON.stringify({
                      type: 'system_stats_data',
                      stats: {
                          cpu: cpuLoad.currentLoad,
                          memory: {
                              used: mem.used,
                              total: mem.total,
                          },
                          disk: {
                              used: fs[0].used,
                              total: fs[0].size,
                          },
                      },
                  }));
              } catch (intervalError) {
                  console.error('Error fetching system stats in interval:', intervalError);
              }
          }, 2000); // Send stats every 2 seconds
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
            Cmd: ['/bin/sh'],
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
