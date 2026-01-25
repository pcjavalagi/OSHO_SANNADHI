// server.js - PRODUCTION READY
require('dotenv').config();

const express = require('express');
const cors = require('cors');
const helmet = require('helmet'); // <--- ADDED HELMET
const bodyParser = require('body-parser');
const path = require('path');
const fs = require('fs');
const { MongoClient, ObjectId, GridFSBucket } = require('mongodb');
const bcrypt = require('bcrypt');
const multer = require('multer');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit'); // Security feature

const app = express();
const port = process.env.PORT || 3000;

// --- CONFIGURATION ---
const uri = process.env.MONGO_URI;
const SECRET_KEY = process.env.JWT_SECRET;
const DB_NAME = "osho_db";

if (!uri || !SECRET_KEY) {
    console.error("CRITICAL ERROR: Missing MONGO_URI or JWT_SECRET in .env file");
    process.exit(1);
}

// --- MIDDLEWARE ---

// 1. Helmet (Security Headers)
// Customized to allow your specific external scripts (YouTube, Google Fonts, CDNs)
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "'unsafe-inline'", "https://cdnjs.cloudflare.com"], 
            scriptSrcAttr: ["'unsafe-inline'"],
            styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com", "https://cdnjs.cloudflare.com"],
            fontSrc: ["'self'", "https://fonts.gstatic.com", "https://cdnjs.cloudflare.com"],
            imgSrc: ["'self'", "data:", "https://via.placeholder.com", "https://images.unsplash.com"],
            connectSrc: ["'self'", "https://cdnjs.cloudflare.com"],
            mediaSrc: ["'self'", "blob:"],
            frameSrc: ["'self'", "https://www.youtube.com", "https://youtube.com"],
        },
    },
    crossOriginEmbedderPolicy: false, // Often needed for loading external resources like images
}));

// 2. CORS (Restrict Access)
app.use(cors({
    origin: [
        'http://localhost:3000',      // Allow local testing
        'http://127.0.0.1:3000',      // Allow local testing IP
        'https://your-domain.com'     // <--- REPLACE WITH YOUR ACTUAL DOMAIN ON DEPLOYMENT
    ],
    credentials: true
}));

app.use(bodyParser.json());

// 3. Rate Limiting (Security: Brute-Force Protection)
const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 20, // Limit each IP to 20 requests per windowMs
    message: { message: "Too many login attempts, please try again later." },
    standardHeaders: true,
    legacyHeaders: false,
});

// 4. Static Files
app.use(express.static(path.join(__dirname)));
const UPLOAD_DIR = path.join(__dirname, 'uploads');
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });
app.use('/uploads', express.static(UPLOAD_DIR));

// 5. Multer Configuration (Fix: Use Disk Storage to prevent Memory Leaks)
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, 'uploads/')
    },
    filename: function (req, file, cb) {
        // Safe filename generation
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, uniqueSuffix + '-' + file.originalname.replace(/ /g, '_'));
    }
});
const upload = multer({ storage: storage });


// --- DATABASE CONNECTION & SERVER LOGIC ---
const client = new MongoClient(uri);

async function run() {
    try {
        await client.connect();
        console.log("✅ Connected successfully to MongoDB");
        
        const db = client.db(DB_NAME);
        const bucket = new GridFSBucket(db, { bucketName: 'media' });

        // Collections
        const productsCol = db.collection("products");
        const usersCol = db.collection("users");
        const insightsCol = db.collection("insights");
        const glimpsesCol = db.collection("glimpses");
        const messagesCol = db.collection("messages");
        const techniquesCol = db.collection("techniques");
        const ordersCol = db.collection("orders");
        const campDetailsCol = db.collection("campDetails");
        const registrationsCol = db.collection("registrations");
        const sannadhiCol = db.collection("sannadhi");
        const heroImagesCol = db.collection("heroImages");
        const imagesCol = db.collection("images");
        const movementsCol = db.collection("movements");
        const roomsCol = db.collection("rooms");
        const recordingsCol = db.collection("recordings");

            // ... inside run() function, after defining collections ...

// Ensure fast lookups for login and duplicate checks
await usersCol.createIndex({ username: 1 }, { unique: true });
await usersCol.createIndex({ email: 1 }, { unique: true, sparse: true }); // Sparse allows null emails if optional

// Ensure users can fetch their own orders/registrations instantly
await registrationsCol.createIndex({ userId: 1 });
await ordersCol.createIndex({ userId: 1 });

console.log("✅ Database Indexes Verified");

        // --- AUTH MIDDLEWARE ---
        function authenticateToken(req, res, next) {
            const authHeader = req.headers['authorization'];
            const token = authHeader && authHeader.split(' ')[1];

            if (!token) return res.sendStatus(401);

            jwt.verify(token, SECRET_KEY, (err, user) => {
                if (err) return res.sendStatus(403);
                req.user = user;
                next();
            });
        }

        function verifyAdmin(req, res, next) {
            authenticateToken(req, res, () => {
                if (req.user && req.user.role === 'admin') {
                    next();
                } else {
                    res.status(403).json({ message: "Admin access required" });
                }
            });
        }

        // --- ROUTES ---

        // Root Route
        app.get('/', (req, res) => {
            res.sendFile(path.join(__dirname, 'index.html'));
        });

        // 1. AUTHENTICATION
        app.post('/api/register', authLimiter, async (req, res) => {
            try {
                const { username, phone, email, address, password } = req.body;
                
                if (!username || !password || !phone) {
                    return res.status(400).json({ message: "Missing required fields" });
                }
                if (!/^\d{10}$/.test(String(phone).trim())) {
                    return res.status(400).json({ message: "Phone must be exactly 10 digits" });
                }
                if (String(password).length < 6) {
                    return res.status(400).json({ message: "Password must be at least 6 characters." });
                }

                const existing = await usersCol.findOne({ username: { $regex: new RegExp(`^${username}$`, 'i') } });
                if (existing) return res.status(400).json({ message: "Username already exists" });

                const hashedPassword = await bcrypt.hash(password, 10);
                await usersCol.insertOne({ username, phone, email, address, password: hashedPassword });
                res.status(201).json({ message: "Registration successful" });
            } catch (e) {
                console.error("Register Error:", e);
                res.status(500).json({ message: "Server error during registration" });
            }
        });

        app.post('/api/login', authLimiter, async (req, res) => {
            try {
                const { username, password } = req.body;
                const user = await usersCol.findOne({ username });

                if (user && await bcrypt.compare(password, user.password)) {
                    const token = jwt.sign({ userId: user._id, username: user.username, role: 'user' }, SECRET_KEY, { expiresIn: '24h' });
                    res.status(200).json({ message: "Login successful", username: user.username, userId: user._id, token });
                } else {
                    res.status(401).json({ message: "Invalid credentials" });
                }
            } catch (e) {
                console.error("Login Error:", e);
                res.status(500).json({ message: "Server error during login" });
            }
        });

        app.post('/api/admin-login', authLimiter, (req, res) => {
            try {
                const { username, password } = req.body;
                // Secure check using ENV variables
                if (username === process.env.ADMIN_USERNAME && password === process.env.ADMIN_PASSWORD) {
                    const token = jwt.sign({ username: username, role: 'admin' }, SECRET_KEY, { expiresIn: '2h' });
                    res.status(200).json({ message: "Admin Login successful", token });
                } else {
                    res.status(401).json({ message: "Invalid Admin Credentials" });
                }
            } catch (e) {
                res.status(500).json({ message: "Server Error" });
            }
        });

        // 2. USER PROFILE
        app.get('/api/users/:id', authenticateToken, async (req, res) => {
            try {
                const user = await usersCol.findOne({ _id: new ObjectId(req.params.id) });
                if (user) {
                    delete user.password;
                    res.status(200).json(user);
                } else {
                    res.status(404).json({ message: "User not found" });
                }
            } catch (e) { res.status(500).json({ message: "Error fetching user" }); }
        });

        app.put('/api/users/:id', authenticateToken, async (req, res) => {
            try {
                const { phone, email, address, password } = req.body;
                if (phone && !/^\d{10}$/.test(String(phone).trim())) {
                    return res.status(400).json({ message: "Phone must be exactly 10 digits" });
                }
                const updates = { phone, email, address };
                if (password && password.length >= 6) updates.password = await bcrypt.hash(password, 10);
                
                await usersCol.updateOne({ _id: new ObjectId(req.params.id) }, { $set: updates });
                res.status(200).json({ message: "Profile updated" });
            } catch (e) { res.status(500).json({ message: "Update failed" }); }
        });

        // 3. ROOMS MANAGEMENT
        app.get('/api/rooms', async (req, res) => {
            try {
                const data = await roomsCol.find({}).toArray();
                res.status(200).json(data);
            } catch (e) { res.status(500).json({ message: "Error fetching rooms" }); }
        });

        app.post('/api/rooms', verifyAdmin, async (req, res) => {
            try {
                const { name, beds } = req.body;
                if (!name || !beds) return res.status(400).json({ message: "Fields required" });
                await roomsCol.insertOne({ name, beds: parseInt(beds) });
                res.status(201).json({ message: "Room Added" });
            } catch (e) { res.status(500).json({ message: "Error adding room" }); }
        });

        app.put('/api/rooms/:id', verifyAdmin, async (req, res) => {
            try {
                const { name, beds } = req.body;
                await roomsCol.updateOne({ _id: new ObjectId(req.params.id) }, { $set: { name, beds: parseInt(beds) } });
                res.status(200).json({ message: "Room Updated" });
            } catch (e) { res.status(500).json({ message: "Error updating room" }); }
        });

        app.delete('/api/rooms/:id', verifyAdmin, async (req, res) => {
            try {
                await roomsCol.deleteOne({ _id: new ObjectId(req.params.id) });
                res.status(200).json({ message: "Room Deleted" });
            } catch (e) { res.status(500).json({ message: "Error deleting room" }); }
        });

        // 4. CAMP DETAILS & REGISTRATION
        app.get('/api/camp-details', async (req, res) => {
            try {
                const details = await campDetailsCol.findOne({});
                const count = await registrationsCol.countDocuments({ status: { $ne: 'Rejected' } });
                res.status(200).json({ ...(details || {}), regCount: count });
            } catch (e) { res.status(500).json({ message: "Error fetching camp details" }); }
        });

        app.post('/api/camp-details', verifyAdmin, async (req, res) => {
            try {
                await campDetailsCol.updateOne({}, { $set: req.body }, { upsert: true });
                res.status(200).json({ message: "Camp Details Updated." });
            } catch (e) { res.status(500).json({ message: "Error updating details" }); }
        });

        app.post('/api/camp-reset', verifyAdmin, async (req, res) => {
            try {
                await registrationsCol.deleteMany({});
                res.status(200).json({ message: "All Registrations have been reset." });
            } catch (e) { res.status(500).json({ message: "Error resetting camp" }); }
        });

        app.post('/api/camp-register', authenticateToken, async (req, res) => {
            try {
                const { userId, username, phone, type, confirmation, roomType, specialReq } = req.body;

                if (!/^\d{10}$/.test(String(phone).trim())) {
                    return res.status(400).json({ message: "Phone must be 10 digits" });
                }
                if (confirmation !== "JAI OSHO") {
                    return res.status(400).json({ message: "Incorrect confirmation text." });
                }

                const details = await campDetailsCol.findOne({});
                const currentCount = await registrationsCol.countDocuments({ status: { $ne: 'Rejected' } });
                const totalSeats = parseInt(details?.totalSeats || 0);

                let status = 'Confirmed';
                if (totalSeats > 0 && currentCount >= totalSeats) {
                    status = 'Waiting';
                }

                await registrationsCol.insertOne({
                    userId: new ObjectId(userId),
                    username,
                    phone,
                    type,
                    roomType,
                    specialReq,
                    status: status,
                    date: new Date()
                });

                if (status === 'Waiting') {
                    res.status(201).json({ message: "Camp Full. Added to Waiting List." });
                } else {
                    res.status(201).json({ message: "Registration Successful! JAI OSHO!" });
                }
            } catch (e) {
                console.error(e);
                res.status(500).json({ message: "Registration failed on server" });
            }
        });

        app.get('/api/camp-registrations', verifyAdmin, async (req, res) => {
            try {
                const list = await registrationsCol.find({}).sort({ date: -1 }).toArray();
                res.status(200).json(list);
            } catch (e) { res.status(500).json({ message: "Error fetching list" }); }
        });

        app.get('/api/my-registrations/:userId', authenticateToken, async (req, res) => {
            try {
                const list = await registrationsCol.find({ userId: new ObjectId(req.params.userId) }).sort({ date: -1 }).toArray();
                res.status(200).json(list);
            } catch (e) { res.status(500).json({ message: "Error fetching data" }); }
        });

        app.put('/api/registrations/:id', authenticateToken, async (req, res) => {
            try {
                const { username, phone, type, status, assignedRoomId, assignedRoomName } = req.body;
                const registrationId = new ObjectId(req.params.id);
                
                const registration = await registrationsCol.findOne({ _id: registrationId });
                if (!registration) return res.status(404).json({ message: "Not found" });

                const isAdmin = req.user.role === 'admin';
                const isOwner = registration.userId.toString() === req.user.userId;

                if (!isAdmin && !isOwner) {
                    return res.status(403).json({ message: "Unauthorized" });
                }

                const updateFields = {};
                if(username) updateFields.username = username;
                if(phone) updateFields.phone = phone;
                if(type) updateFields.type = type;

                if (isAdmin) {
                    if(status) updateFields.status = status;
                    if(assignedRoomId) updateFields.assignedRoomId = assignedRoomId;
                    if(assignedRoomName) updateFields.assignedRoomName = assignedRoomName;
                }

                await registrationsCol.updateOne({ _id: registrationId }, { $set: updateFields });
                res.status(200).json({ message: "Updated successfully" });
            } catch (e) { res.status(500).json({ message: "Update Failed" }); }
        });

        app.delete('/api/registrations/:id', verifyAdmin, async (req, res) => {
            try {
                await registrationsCol.deleteOne({ _id: new ObjectId(req.params.id) });
                res.status(200).json({ message: "Deleted" });
            } catch (e) { res.status(500).json({ message: "Error deleting" }); }
        });

        // 5. CONTENT ROUTES (Sannadhi, Hero, Products)
        // Helper to generate CRUD routes
        const createCrudRoutes = (path, collection) => {
            app.get(path, async (req, res) => {
                try {
                    const data = await collection.find({}).toArray();
                    res.status(200).json(data);
                } catch(e) { res.status(500).json({message: "Fetch error"}); }
            });
            app.post(path, verifyAdmin, async (req, res) => {
                try {
                    await collection.insertOne(req.body);
                    res.status(201).json({ message: "Created" });
                } catch(e) { res.status(500).json({message: "Create error"}); }
            });
            app.delete(`${path}/:id`, verifyAdmin, async (req, res) => {
                try {
                    await collection.deleteOne({ _id: new ObjectId(req.params.id) });
                    res.status(200).json({ message: "Deleted" });
                } catch(e) { res.status(500).json({message: "Delete error"}); }
            });
        };

        createCrudRoutes('/api/sannadhi', sannadhiCol);
        createCrudRoutes('/api/hero-images', heroImagesCol);
        createCrudRoutes('/api/products', productsCol);
        createCrudRoutes('/api/movements', movementsCol);
        createCrudRoutes('/api/techniques', techniquesCol);
        createCrudRoutes('/api/insights', insightsCol);
        createCrudRoutes('/api/glimpses', glimpsesCol);

        // 6. MEDIA UPLOAD (Fixed for Large Files & Memory)
        app.post('/api/upload-url', verifyAdmin, async (req, res) => {
            try {
                const { url, type, name } = req.body;
                if(!url) return res.status(400).json({message: "URL required"});

                const doc = {
                    name: name || 'Media URL',
                    type: type || 'video',
                    filename: 'external-url',
                    path: url,
                    uploadedAt: new Date(),
                    isExternal: true
                };
                await imagesCol.insertOne(doc);
                res.status(201).json({ message: "URL Saved", doc });
            } catch (e) { res.status(500).json({ message: "Failed to save URL" }); }
        });

        // The Big Fix: Stream file from Disk to GridFS
        app.post('/api/upload-media', upload.single('file'), verifyAdmin, (req, res) => {
            const file = req.file;
            if (!file) return res.status(400).json({ message: "No file provided" });

            const type = req.body.type || 'image';
            const name = req.body.name || file.originalname;
            const inGallery = req.body.inGallery === 'true';
            
            // Generate a filename for GridFS
            const gridFilename = `${Date.now()}-${file.originalname.replace(/ /g, '_')}`;

            // Open upload stream to GridFS
            const uploadStream = bucket.openUploadStream(gridFilename, {
                contentType: file.mimetype
            });

            // Read from disk and pipe to GridFS
            const readStream = fs.createReadStream(file.path);
            
            readStream.pipe(uploadStream)
                .on('error', (err) => {
                    console.error("GridFS Upload Error:", err);
                    res.status(500).json({ message: "Database Upload Failed" });
                })
                .on('finish', async () => {
                    // Clean up temp file
                    fs.unlink(file.path, (err) => {
                        if (err) console.error("Temp file deletion error:", err);
                    });

                    // Save metadata
                    const doc = {
                        name,
                        type,
                        filename: gridFilename,
                        path: `/api/media/stream/${gridFilename}`, // Stream URL
                        uploadedAt: new Date(),
                        isExternal: false,
                        inGallery: inGallery,
                        gridFsId: uploadStream.id
                    };

                    await imagesCol.insertOne(doc);
                    res.status(201).json({ message: "Media Uploaded Successfully", doc });
                });
        });

        app.get('/api/media', async (req, res) => {
            try {
                const data = await imagesCol.find({}).sort({ uploadedAt: -1 }).toArray();
                res.status(200).json(data);
            } catch(e) { res.status(500).json({message: "Error"}); }
        });

        app.delete('/api/media/:id', verifyAdmin, async (req, res) => {
            try {
                const img = await imagesCol.findOne({ _id: new ObjectId(req.params.id) });
                if (img && !img.isExternal && img.gridFsId) {
                    await bucket.delete(img.gridFsId); // Remove from GridFS
                }
                await imagesCol.deleteOne({ _id: new ObjectId(req.params.id) });
                res.status(200).json({ message: "Media Deleted" });
            } catch (err) {
                // If GridFS fails (file not found), still delete metadata
                await imagesCol.deleteOne({ _id: new ObjectId(req.params.id) });
                res.status(200).json({ message: "Media Record Deleted" });
            }
        });

        // 7. STREAM MEDIA ROUTE
        app.get('/api/media/stream/:filename', async (req, res) => {
            try {
                const filename = req.params.filename;
                const files = await bucket.find({ filename }).toArray();
                
                if (!files || files.length === 0) return res.status(404).send('File not found');

                res.setHeader('Content-Type', files[0].contentType || 'application/octet-stream');
                
                const downloadStream = bucket.openDownloadStreamByName(filename);
                downloadStream.pipe(res);
                downloadStream.on('error', () => res.sendStatus(404));

            } catch (err) {
                console.error(err);
                res.status(500).send('Stream Error');
            }
        });

        // 8. ORDERS
        app.post('/api/checkout', authenticateToken, async (req, res) => {
            try {
                const { userId, cart, password } = req.body;
                const user = await usersCol.findOne({ _id: new ObjectId(userId) });
                
                if (!user || !(await bcrypt.compare(password, user.password))) {
                    return res.status(401).json({ message: "Incorrect Password." });
                }

                let total = 0;
                cart.forEach(item => total += item.price);
                total += 100; // Shipping/Handling

                const order = {
                    userId: new ObjectId(userId),
                    username: user.username,
                    items: cart,
                    total: total,
                    date: new Date(),
                    address: user.address,
                    status: 'Pending'
                };

                await ordersCol.insertOne(order);
                
                // Reduce Stock
                for (const item of cart) {
                    try { await productsCol.updateOne({ _id: new ObjectId(item._id) }, { $inc: { stock: -1 } }); } catch(e){}
                }
                res.status(200).json({ message: "Order Placed" });
            } catch(e) { res.status(500).json({ message: "Checkout Failed" }); }
        });

        app.get('/api/orders', authenticateToken, async (req, res) => {
            try {
                const { userId, admin } = req.query;
                let query = {};
                
                if (admin === 'true') {
                    if (req.user.role !== 'admin') return res.status(403).json({message: "Unauthorized"});
                    query = {};
                } else if (userId) {
                    if (req.user.userId !== userId) return res.status(403).json({message: "Unauthorized"});
                    query = { userId: new ObjectId(userId) };
                } else {
                    return res.status(400).json({message: "Bad Request"});
                }

                const orders = await ordersCol.find(query).sort({ date: -1 }).toArray();
                res.status(200).json(orders);
            } catch(e) { res.status(500).json({ message: "Fetch Failed" }); }
        });

        app.put('/api/orders/:id', verifyAdmin, async (req, res) => {
            try {
                const { status } = req.body;
                await ordersCol.updateOne({ _id: new ObjectId(req.params.id) }, { $set: { status } });
                res.status(200).json({ message: "Order Updated" });
            } catch(e) { res.status(500).json({ message: "Update Failed" }); }
        });

        app.delete('/api/orders/:id', verifyAdmin, async (req, res) => {
            try {
                await ordersCol.deleteOne({ _id: new ObjectId(req.params.id) });
                res.status(200).json({ message: "Order Deleted" });
            } catch(e) { res.status(500).json({ message: "Delete Failed" }); }
        });

        // 9. MESSAGES
        app.post('/api/contact', async (req, res) => {
            try {
                await messagesCol.insertOne({ ...req.body, date: new Date() });
                res.status(201).json({ message: "Message sent" });
            } catch(e) { res.status(500).json({ message: "Error sending message" }); }
        });

        app.get('/api/messages', verifyAdmin, async (req, res) => {
            try {
                const msgs = await messagesCol.find({}).sort({ date: -1 }).toArray();
                res.status(200).json(msgs);
            } catch(e) { res.status(500).json({ message: "Error fetching messages" }); }
        });
        
        app.delete('/api/messages/:id', verifyAdmin, async (req, res) => {
            try {
                await messagesCol.deleteOne({ _id: new ObjectId(req.params.id) });
                res.status(200).json({ message: "Message deleted" });
            } catch(e) { res.status(500).json({ message: "Error deleting message" }); }
        });

        // 10. RECORDINGS (With Auto-Delete)
        app.get('/api/recordings', async (req, res) => {
            try {
                const data = await recordingsCol.find({}).sort({ uploadedAt: -1 }).toArray();
                res.status(200).json(data);
            } catch(e) { res.status(500).json({ message: "Error fetching recordings" }); }
        });

        app.post('/api/recordings', verifyAdmin, async (req, res) => {
            try {
                const { title, desc, link } = req.body;
                if (!title || !link) return res.status(400).json({ message: "Title and Link are required" });
                
                await recordingsCol.insertOne({ title, desc, link, uploadedAt: new Date() });
                res.status(201).json({ message: "Recording Added" });
            } catch(e) { res.status(500).json({ message: "Error adding recording" }); }
        });

        app.delete('/api/recordings/:id', verifyAdmin, async (req, res) => {
            try {
                await recordingsCol.deleteOne({ _id: new ObjectId(req.params.id) });
                res.status(200).json({ message: "Recording Deleted" });
            } catch(e) { res.status(500).json({ message: "Error deleting" }); }
        });

        // Auto Delete Recordings older than 7 days
        setInterval(async () => {
            try {
                const sevenDaysAgo = new Date();
                sevenDaysAgo.setDate(sevenDaysAgo.getDate() - 7);
                const result = await recordingsCol.deleteMany({ uploadedAt: { $lt: sevenDaysAgo } });
                if (result.deletedCount > 0) console.log(`Deleted ${result.deletedCount} old recordings.`);
            } catch (e) { console.error("Auto-delete error:", e); }
        }, 3600000); // 1 Hour

        // Start Server
        app.listen(port, () => {
            console.log(`🚀 Server running on port ${port}`);
            console.log(`👉 Local: http://localhost:${port}`); 
            console.log(`📂 Serving static files from: ${__dirname}`);
        });

    } catch (err) {
        console.error("❌ Failed to connect to MongoDB:", err);
    }

}

run().catch(console.dir);