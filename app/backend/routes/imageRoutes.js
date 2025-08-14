const express = require('express');
const router = express.Router();
const Docker = require('dockerode');
const docker = new Docker({ socketPath: '/var/run/docker.sock' });
const { protect, authorize } = require('../middleware/authMiddleware');

// Get all images
router.get('/', protect, authorize('Admin', 'Developer', 'Viewer'), async (req, res) => {
    try {
        const images = await docker.listImages({});
        res.json(images);
    } catch (error) {
        console.error('Error fetching images:', error);
        res.status(500).json({ message: 'Error fetching images', error: error.message });
    }
});

// Remove an image
router.delete('/:id', protect, authorize('Admin'), async (req, res) => {
    try {
        const image = docker.getImage(req.params.id);
        await image.remove({ force: req.query.force === 'true' });
        res.status(200).json({ message: `Image ${req.params.id} removed successfully.` });
    } catch (error) {
        console.error(`Error removing image ${req.params.id}:`, error);
        if (error.statusCode === 404) {
            res.status(404).json({ message: `Image ${req.params.id} not found.` });
        } else if (error.statusCode === 409) {
            res.status(409).json({ message: 'This image is in use by one or more containers.' });
        } else {
            res.status(500).json({ message: 'Error removing image', error: error.message });
        }
    }
});

// Pull an image (asynchronous)
router.post('/pull', protect, authorize('Admin', 'Developer'), (req, res) => {
    const { imageName } = req.body;
    if (!imageName) {
        return res.status(400).json({ message: 'Image name is required.' });
    }

    // Immediately respond to the client
    res.status(202).json({ message: `Pulling image '${imageName}'. This may take a while. Please refresh the image list later to see the result.` });

    // Perform the pull in the background
    docker.pull(imageName, (err, stream) => {
        if (err) {
            console.error(`Error initiating image pull for ${imageName}:`, err);
            // Cannot send response here
            return;
        }
        docker.modem.followProgress(stream, (err, output) => {
            if (err) {
                console.error(`Error during image pull ${imageName}:`, err);
            } else {
                console.log(`Image ${imageName} pulled successfully.`);
            }
        });
    });
});

// Tag an image
router.post('/:id/tag', protect, authorize('Admin', 'Developer'), async (req, res) => {
    const { repo, tag } = req.body;
    if (!repo) {
        return res.status(400).json({ message: 'Repository name is required.' });
    }
    try {
        const image = docker.getImage(req.params.id);
        await image.tag({ repo, tag });
        res.status(200).json({ message: `Image ${req.params.id} tagged as ${repo}:${tag || 'latest'}` });
    } catch (error) {
        console.error(`Error tagging image ${req.params.id}:`, error);
        if (error.statusCode === 404) {
            res.status(404).json({ message: `Image ${req.params.id} not found.` });
        } else {
            res.status(500).json({ message: 'Error tagging image', error: error.message });
        }
    }
});

// Build an image from a remote git repository (asynchronous)
router.post('/build', protect, authorize('Admin', 'Developer'), (req, res) => {
    const { remote, t: tag } = req.body; // 't' for tag, following Docker CLI conventions
    if (!remote) {
        return res.status(400).json({ message: 'Remote git repository URL is required.' });
    }

    const buildOptions = {
        remote: remote,
        t: tag,
    };

    // Immediately respond to the client
    res.status(202).json({ message: `Build started from ${remote}. This may take a while. Please refresh the image list later to see the result.` });

    // Perform the build in the background
    docker.buildImage(null, buildOptions, (err, stream) => {
        if (err) {
            console.error(`Error initiating image build from ${remote}:`, err);
            // Cannot send response here
            return;
        }

        docker.modem.followProgress(stream, (err, output) => {
            if (err) {
                console.error(`Error during image build from ${remote}:`, err);
            } else {
                console.log(`Image built successfully from ${remote}.`);
            }
        });
    });
});

module.exports = router;
