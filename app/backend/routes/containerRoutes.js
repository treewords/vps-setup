const express = require('express');
const router = express.Router();
const Docker = require('dockerode');
const docker = new Docker({ socketPath: '/var/run/docker.sock' });
const { protect, authorize } = require('../middleware/authMiddleware');

// Create and start a new container
router.post('/create', protect, authorize('Admin', 'Developer'), async (req, res) => {
    try {
        const container = await docker.createContainer(req.body);
        await container.start();
        res.status(201).json({ message: 'Container created and started successfully', id: container.id });
    } catch (error) {
        console.error('Error creating container:', error);
        if (error.statusCode === 404) {
            res.status(404).json({ message: `Image not found: ${req.body.Image}` });
        } else if (error.statusCode === 409) {
            res.status(409).json({ message: `Container name "${req.body.name}" is already in use.` });
        }
        else {
            res.status(500).json({ message: 'Error creating container', error: error.message });
        }
    }
});

// List all containers
router.get('/', protect, authorize('Admin', 'Developer', 'Viewer'), async (req, res) => {
  try {
    const containers = await docker.listContainers({ all: true });
    res.json(containers);
  } catch (error) {
    console.error('Error fetching containers:', error);
    res.status(500).json({ message: 'Error fetching containers', error: error.message });
  }
});

// Inspect a container
router.get('/:id', protect, authorize('Admin', 'Developer', 'Viewer'), async (req, res) => {
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
router.get('/:id/logs', protect, authorize('Admin', 'Developer', 'Viewer'), async (req, res) => {
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
router.post('/:id/start', protect, authorize('Admin', 'Developer'), async (req, res) => {
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
router.post('/:id/stop', protect, authorize('Admin', 'Developer'), async (req, res) => {
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
router.post('/:id/restart', protect, authorize('Admin', 'Developer'), async (req, res) => {
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
router.post('/:id/pause', protect, authorize('Admin', 'Developer'), async (req, res) => {
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
router.post('/:id/unpause', protect, authorize('Admin', 'Developer'), async (req, res) => {
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
router.delete('/:id', protect, authorize('Admin'), async (req, res) => {
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

module.exports = router;
