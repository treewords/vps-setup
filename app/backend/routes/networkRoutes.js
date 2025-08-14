const express = require('express');
const router = express.Router();
const Docker = require('dockerode');
const docker = new Docker({ socketPath: '/var/run/docker.sock' });
const { protect, authorize } = require('../middleware/authMiddleware');

// List all networks
router.get('/', protect, authorize('Admin', 'Developer', 'Viewer'), async (req, res) => {
    try {
        const networks = await docker.listNetworks();
        res.json(networks);
    } catch (error) {
        console.error('Error fetching networks:', error);
        res.status(500).json({ message: 'Error fetching networks', error: error.message });
    }
});

// Inspect a network
router.get('/:id', protect, authorize('Admin', 'Developer', 'Viewer'), async (req, res) => {
    try {
        const network = docker.getNetwork(req.params.id);
        const data = await network.inspect();
        res.json(data);
    } catch (error) {
        console.error(`Error inspecting network ${req.params.id}:`, error);
        if (error.statusCode === 404) {
            res.status(404).json({ message: `Network ${req.params.id} not found.` });
        } else {
            res.status(500).json({ message: 'Error inspecting network', error: error.message });
        }
    }
});

// Create a new network
router.post('/create', protect, authorize('Admin', 'Developer'), async (req, res) => {
    try {
        const network = await docker.createNetwork(req.body);
        res.status(201).json({ message: 'Network created successfully', id: network.id });
    } catch (error) {
        console.error('Error creating network:', error);
        res.status(500).json({ message: 'Error creating network', error: error.message });
    }
});

// Remove a network
router.delete('/:id', protect, authorize('Admin'), async (req, res) => {
    try {
        const network = docker.getNetwork(req.params.id);
        await network.remove();
        res.status(200).json({ message: `Network ${req.params.id} removed successfully.` });
    } catch (error) {
        console.error(`Error removing network ${req.params.id}:`, error);
        if (error.statusCode === 404) {
            res.status(404).json({ message: `Network ${req.params.id} not found.` });
        } else {
            res.status(500).json({ message: 'Error removing network', error: error.message });
        }
    }
});

// Connect a container to a network
router.post('/:id/connect', protect, authorize('Admin', 'Developer'), async (req, res) => {
    try {
        const network = docker.getNetwork(req.params.id);
        await network.connect({ Container: req.body.containerId });
        res.status(200).json({ message: `Container ${req.body.containerId} connected to network ${req.params.id}` });
    } catch (error) {
        console.error(`Error connecting container to network ${req.params.id}:`, error);
        if (error.statusCode === 404) {
            res.status(404).json({ message: `Network or container not found.` });
        } else {
            res.status(500).json({ message: 'Error connecting container to network', error: error.message });
        }
    }
});

// Disconnect a container from a network
router.post('/:id/disconnect', protect, authorize('Admin', 'Developer'), async (req, res) => {
    try {
        const network = docker.getNetwork(req.params.id);
        await network.disconnect({ Container: req.body.containerId });
        res.status(200).json({ message: `Container ${req.body.containerId} disconnected from network ${req.params.id}` });
    } catch (error) {
        console.error(`Error disconnecting container from network ${req.params.id}:`, error);
        if (error.statusCode === 404) {
            res.status(404).json({ message: `Network or container not found.` });
        } else {
            res.status(500).json({ message: 'Error disconnecting container from network', error: error.message });
        }
    }
});

module.exports = router;
