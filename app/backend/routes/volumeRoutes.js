const express = require('express');
const router = express.Router();
const Docker = require('dockerode');
const docker = new Docker({ socketPath: '/var/run/docker.sock' });
const { protect, authorize } = require('../middleware/authMiddleware');

// List all volumes
router.get('/', protect, authorize('Admin', 'Developer', 'Viewer'), async (req, res) => {
    try {
        const { Volumes } = await docker.listVolumes();
        res.json(Volumes);
    } catch (error) {
        console.error('Error fetching volumes:', error);
        res.status(500).json({ message: 'Error fetching volumes', error: error.message });
    }
});

// Inspect a volume
router.get('/:name', protect, authorize('Admin', 'Developer', 'Viewer'), async (req, res) => {
    try {
        const volume = docker.getVolume(req.params.name);
        const data = await volume.inspect();
        res.json(data);
    } catch (error) {
        console.error(`Error inspecting volume ${req.params.name}:`, error);
        if (error.statusCode === 404) {
            res.status(404).json({ message: `Volume ${req.params.name} not found.` });
        } else {
            res.status(500).json({ message: 'Error inspecting volume', error: error.message });
        }
    }
});

// Create a new volume
router.post('/create', protect, authorize('Admin', 'Developer'), async (req, res) => {
    try {
        const volume = await docker.createVolume(req.body);
        res.status(201).json({ message: 'Volume created successfully', name: volume.name });
    } catch (error) {
        console.error('Error creating volume:', error);
        res.status(500).json({ message: 'Error creating volume', error: error.message });
    }
});

// Remove a volume
router.delete('/:name', protect, authorize('Admin'), async (req, res) => {
    try {
        const volume = docker.getVolume(req.params.name);
        await volume.remove();
        res.status(200).json({ message: `Volume ${req.params.name} removed successfully.` });
    } catch (error) {
        console.error(`Error removing volume ${req.params.name}:`, error);
        if (error.statusCode === 404) {
            res.status(404).json({ message: `Volume ${req.params.name} not found.` });
        } else {
            res.status(500).json({ message: 'Error removing volume', error: error.message });
        }
    }
});

// Backup a volume
router.post('/:name/backup', protect, authorize('Admin'), async (req, res) => {
    const volumeName = req.params.name;
    const backupDir = '/opt/backups'; // This should be configurable
    const backupFileName = `${volumeName}-backup-${new Date().toISOString().slice(0, 10)}.tar.gz`;
    const containerBackupPath = `/backup/${backupFileName}`;

    try {
        const container = await docker.createContainer({
            Image: 'alpine',
            Tty: false,
            Cmd: ['tar', '-czf', containerBackupPath, '-C', '/volume', '.'],
            HostConfig: {
                Mounts: [
                    {
                        Target: '/volume',
                        Source: volumeName,
                        Type: 'volume',
                        ReadOnly: true
                    },
                    {
                        Target: '/backup',
                        Source: backupDir,
                        Type: 'bind'
                    }
                ],
                AutoRemove: true
            }
        });

        await container.start();
        const statusCode = await container.wait();

        if (statusCode.StatusCode !== 0) {
            throw new Error(`Backup container exited with status code: ${statusCode.StatusCode}`);
        }

        res.status(200).json({ message: `Volume ${volumeName} backed up successfully to ${backupDir}/${backupFileName}.` });

    } catch (error) {
        console.error(`Error backing up volume ${volumeName}:`, error);
        if (error.message.includes('No such image: alpine')) {
            return res.status(400).json({ message: 'The "alpine" image is not available. Please pull it first.' });
        }
        res.status(500).json({ message: 'Error backing up volume', error: error.message });
    }
});

module.exports = router;
